<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel;

use Kampe\TelegramTwoFactor\Results\ChallengeResult;
use Kampe\TelegramTwoFactor\Results\LinkRequest;
use Kampe\TelegramTwoFactor\Results\VerificationResult;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;

/**
 * Convenience methods on the user model.
 *
 * Sugar over the service, nothing more: everything here is one call on
 * TelegramTwoFactor with the model's key passed in. Use the service directly if
 * you would rather not put behaviour on the model.
 *
 * @mixin \Illuminate\Database\Eloquent\Model
 */
trait HasTelegramTwoFactor
{
    public function hasTelegramTwoFactor(): bool
    {
        return $this->telegramTwoFactor()->isLinked((string) $this->getKey());
    }

    /**
     * Start the deeplink flow. Returns a token and a t.me URL to show the user.
     */
    public function startTelegramLink(): LinkRequest
    {
        return $this->telegramTwoFactor()->startDeepLink((string) $this->getKey());
    }

    /**
     * Finish the paste flow with a code the user read out of the bot chat.
     */
    public function completeTelegramLink(string $code): \Kampe\TelegramTwoFactor\Results\LinkResult
    {
        return $this->telegramTwoFactor()->completePasteLink((string) $this->getKey(), $code);
    }

    /**
     * Send a code to this user's linked chat.
     */
    public function sendTelegramCode(string $purpose = 'login'): ChallengeResult
    {
        return $this->telegramTwoFactor()->push((string) $this->getKey(), $purpose);
    }

    /**
     * Check a code this user submitted.
     */
    public function verifyTelegramCode(string $code, ?string $purpose = null): VerificationResult
    {
        return $this->telegramTwoFactor()->verify((string) $this->getKey(), $code, $purpose);
    }

    /**
     * Remove the factor, proving possession of it with a current code.
     */
    public function unlinkTelegram(string $code): VerificationResult
    {
        return $this->telegramTwoFactor()->unlink((string) $this->getKey(), $code);
    }

    protected function telegramTwoFactor(): TelegramTwoFactor
    {
        return app(TelegramTwoFactor::class);
    }
}
