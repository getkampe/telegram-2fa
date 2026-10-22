<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Webhook;

use Kampe\TelegramTwoFactor\Config;
use Kampe\TelegramTwoFactor\Contracts\Clock;
use Kampe\TelegramTwoFactor\Contracts\CodeStore;
use Kampe\TelegramTwoFactor\Contracts\Logger;
use Kampe\TelegramTwoFactor\Contracts\Messages;
use Kampe\TelegramTwoFactor\Contracts\TelegramClient;
use Kampe\TelegramTwoFactor\ErrorCode;
use Kampe\TelegramTwoFactor\Support\NullLogger;
use Kampe\TelegramTwoFactor\Support\SystemClock;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;

/**
 * Turns a verified Telegram update into protocol actions.
 *
 * Framework-free: hand it a decoded update array and it does the work. Routing,
 * request parsing and the secret-token check belong to the caller — in Laravel,
 * to Laravel\WebhookController and Laravel\VerifyTelegramWebhook.
 *
 * Commands handled: /start (with or without a deeplink payload), /code, /status,
 * /unlink, /help. Anything else gets a short reply rather than silence, because
 * silence from a security bot reads as a broken security bot.
 */
final class UpdateHandler
{
    private readonly Logger $logger;

    private readonly Clock $clock;

    /** @var array<string, callable(string, string): void> */
    private array $extraCommands = [];

    public function __construct(
        private readonly TelegramTwoFactor $tfa,
        private readonly Config $config,
        private readonly CodeStore $store,
        private readonly TelegramClient $telegram,
        private readonly Messages $messages,
        ?Logger $logger = null,
        /**
         * Produces the label shown in the link confirmation message, given a
         * user id. Default shows nothing identifying. Pass something partially
         * masked if you want it: this message lands in a chat.
         *
         * @var null|callable(string): string
         */
        private readonly mixed $accountLabel = null,
        ?Clock $clock = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
        $this->clock = $clock ?? new SystemClock();
    }

    /**
     * Register an application command, for example /balance.
     *
     * The callback receives the chat id and the raw argument string. It is
     * invoked only after the update has been verified as coming from Telegram,
     * but the argument is still user input: treat it as such.
     *
     * @param  callable(string, string): void  $handler
     */
    public function on(string $command, callable $handler): self
    {
        $this->extraCommands[strtolower(ltrim($command, '/'))] = $handler;

        return $this;
    }

    /**
     * Handle one update.
     *
     * @param  array<string, mixed>  $update  The decoded update body.
     * @return bool Whether the update was acted on. Either way the caller should
     *              answer 200: a non-2xx response makes Telegram retry and queue
     *              every later update behind this one.
     */
    public function handle(array $update): bool
    {
        $claim = $this->claim($update);

        if ($claim === false) {
            return false;
        }

        try {
            $handled = $this->dispatch($update);
        } catch (\Throwable $e) {
            // Release the claim so that Telegram's retry is processed rather
            // than discarded as a duplicate. Marking an update done before its
            // work succeeds turns one transient failure into a permanently lost
            // operation.
            if ($claim !== null) {
                $this->store->forget($claim);
            }

            throw $e;
        }

        // Only now is it really handled, so hold the claim for the full window.
        if ($claim !== null) {
            $this->store->put($claim, 'done', $this->config->updateDedupeTtl);
        }

        return $handled;
    }

    /**
     * @param  array<string, mixed>  $update
     */
    private function dispatch(array $update): bool
    {
        if (isset($update['callback_query'])) {
            return $this->handleCallback($update['callback_query']);
        }

        $message = $update['message'] ?? null;

        if (! is_array($message)) {
            return false;
        }

        $chatId = $this->chatIdOf($message);
        $text = is_string($message['text'] ?? null) ? trim($message['text']) : '';

        if ($chatId === null || $text === '') {
            return false;
        }

        if (($message['chat']['type'] ?? 'private') !== 'private') {
            return false;
        }

        if (! str_starts_with($text, '/')) {
            // Codes travel application-to-user, never user-to-bot, so free text
            // is not a code to be checked. Nudging rather than parsing also
            // means a user who pastes a code into the wrong window has not just
            // handed it to the bot's logs.
            $this->telegram->sendMessage($chatId, $this->messages->unknownCommand());

            return false;
        }

        [$command, $argument] = $this->parseCommand($text);

        $this->logger->info('telegram-2fa: command', [
            'command' => $command,
            'update_id' => $update['update_id'] ?? null,
        ]);

        return match ($command) {
            'start' => $this->start($chatId, $argument),
            'code', 'otp', '2fa' => $this->code($chatId),
            'status' => $this->status($chatId),
            'link' => $this->link($chatId),
            'unlink' => $this->unlinkHint($chatId),
            'help' => $this->help($chatId),
            default => $this->dispatchExtra($command, $chatId, $argument),
        };
    }

    // ------------------------------------------------------------------ commands

    private function start(string $chatId, string $payload): bool
    {
        if ($payload === '') {
            return $this->help($chatId);
        }

        $result = $this->tfa->completeDeepLink($payload, $chatId);

        if ($result->ok && $result->identity !== null) {
            $label = $this->accountLabel !== null
                ? (string) ($this->accountLabel)($result->identity->userId)
                : 'your account';

            $this->telegram->sendMessage(
                $chatId,
                $this->messages->linkSucceeded($label, $this->config->appName),
            );

            return true;
        }

        $this->telegram->sendMessage(
            $chatId,
            $result->error === ErrorCode::AlreadyLinked
                ? $this->messages->alreadyLinked()
                : $this->messages->linkTokenInvalid(),
        );

        return false;
    }

    private function link(string $chatId): bool
    {
        if ($this->tfa->identityForChat($chatId)?->isVerified() === true) {
            $this->telegram->sendMessage($chatId, $this->messages->alreadyLinked());

            return false;
        }

        $request = $this->tfa->startPasteLink($chatId);

        $this->telegram->sendMessage(
            $chatId,
            $this->messages->linkInstructions(
                $request->token,
                $this->config->linkTtl,
                $this->config->appName,
            ),
        );

        return true;
    }

    private function code(string $chatId): bool
    {
        // pull() sends the code itself, so the plaintext never reaches this class.
        $result = $this->tfa->pull($chatId);

        if ($result->ok) {
            return true;
        }

        $this->telegram->sendMessage($chatId, match ($result->error) {
            ErrorCode::NotLinked => $this->messages->notLinked($this->config->appName),
            ErrorCode::Cooldown => $this->messages->cooldown(
                $result->retryAfter($this->clock->now())
            ),
            default => $this->messages->unknownCommand(),
        });

        return false;
    }

    private function status(string $chatId): bool
    {
        $identity = $this->tfa->identityForChat($chatId);

        $this->telegram->sendMessage(
            $chatId,
            $identity?->isVerified() === true
                ? $this->messages->welcome(true, $this->config->appName)
                : $this->messages->notLinked($this->config->appName),
        );

        return true;
    }

    /**
     * Unlinking is not done from the chat.
     *
     * Whoever holds the phone can already read the codes; letting them also
     * remove the factor, with no session and no password, turns a stolen phone
     * into a permanently weakened account. The chat gets instructions instead.
     */
    private function unlinkHint(string $chatId): bool
    {
        if ($this->tfa->identityForChat($chatId)?->isVerified() !== true) {
            $this->telegram->sendMessage($chatId, $this->messages->notLinked($this->config->appName));

            return false;
        }

        $this->telegram->sendMessage(
            $chatId,
            $this->messages->unlinkInstructions($this->config->appName),
        );

        return true;
    }

    private function help(string $chatId): bool
    {
        $this->telegram->sendMessage(
            $chatId,
            $this->messages->welcome(
                $this->tfa->identityForChat($chatId)?->isVerified() === true,
                $this->config->appName,
            ),
        );

        return true;
    }

    private function dispatchExtra(string $command, string $chatId, string $argument): bool
    {
        $handler = $this->extraCommands[$command] ?? null;

        if ($handler === null) {
            $this->telegram->sendMessage($chatId, $this->messages->unknownCommand());

            return false;
        }

        $handler($chatId, $argument);

        return true;
    }

    // ------------------------------------------------------------------ plumbing

    private function handleCallback(array $callbackQuery): bool
    {
        $id = (string) ($callbackQuery['id'] ?? '');
        $data = (string) ($callbackQuery['data'] ?? '');
        $chatId = $this->chatIdOf($callbackQuery['message'] ?? []);

        if ($id !== '') {
            // Acknowledge first, or the user's client spins for ten seconds.
            $this->telegram->answerCallbackQuery($id);
        }

        if ($chatId === null) {
            return false;
        }

        return match ($data) {
            'code' => $this->code($chatId),
            'status' => $this->status($chatId),
            'link' => $this->link($chatId),
            'help' => $this->help($chatId),
            default => false,
        };
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function parseCommand(string $text): array
    {
        $parts = preg_split('/\s+/', $text, 2) ?: [];
        $command = strtolower(ltrim($parts[0] ?? '', '/'));

        // In groups Telegram appends the bot name: /code@kampe_bot.
        if (str_contains($command, '@')) {
            $command = strstr($command, '@', true) ?: $command;
        }

        return [$command, trim($parts[1] ?? '')];
    }

    /**
     * @param  array<string, mixed>  $message
     */
    private function chatIdOf(array $message): ?string
    {
        $chatId = $message['chat']['id'] ?? null;

        return is_int($chatId) || is_string($chatId) ? (string) $chatId : null;
    }

    /**
     * Claim an update, so that exactly one attempt processes it.
     *
     * Telegram retries an update it believes was not delivered, and delivers
     * concurrently, so the same update_id can arrive more than once and at the
     * same time. Without a claim a retried /code mints a second code and resets
     * the cooldown.
     *
     * add() is the whole mechanism: checking for a marker and then writing one
     * is two operations, and two simultaneous deliveries both find nothing and
     * both proceed.
     *
     * @param  array<string, mixed>  $update
     * @return string|false|null The claim key to settle, false when this update
     *                           is already claimed, null when deduplication is
     *                           off or the update carries no id.
     */
    private function claim(array $update): string|false|null
    {
        if (! $this->config->dedupeUpdates) {
            return null;
        }

        $updateId = $update['update_id'] ?? null;

        if (! is_int($updateId) && ! is_string($updateId)) {
            return null;
        }

        $key = $this->config->key('update', (string) $updateId);

        // A short claim, not the full window: if this process dies mid-handling
        // the claim lapses on its own and a later retry can pick the update up,
        // rather than it being lost until the dedupe window expires.
        if (! $this->store->add($key, 'claimed', max(30, min(120, $this->config->updateDedupeTtl)))) {
            $this->logger->info('telegram-2fa: duplicate update dropped', ['update_id' => $updateId]);

            return false;
        }

        return $key;
    }
}
