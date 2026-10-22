<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Kampe\TelegramTwoFactor\Contracts\Logger;
use Kampe\TelegramTwoFactor\Webhook\UpdateHandler;
use Throwable;

/**
 * The webhook endpoint.
 *
 * Authentication happens in VerifyTelegramWebhook, before this runs.
 */
final class WebhookController
{
    public function __construct(
        private readonly UpdateHandler $handler,
        private readonly Logger $logger,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        try {
            $this->handler->handle($request->all());
        } catch (Throwable $e) {
            // Log the failure, not the payload. An update body contains the
            // message text, and for this bot the message text is where codes
            // and deeplink tokens live.
            $this->logger->error('telegram-2fa: webhook handler failed', [
                'exception' => $e::class,
                'message' => $e->getMessage(),
                'update_id' => $request->input('update_id'),
            ]);
        }

        // Always 200, even on failure. Telegram retries a non-2xx response with
        // backoff and holds every later update behind it, so one bad update
        // would stall the whole bot.
        return response()->json(['ok' => true]);
    }
}
