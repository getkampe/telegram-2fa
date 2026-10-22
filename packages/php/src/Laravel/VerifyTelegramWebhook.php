<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel;

use Closure;
use Illuminate\Http\Request;
use Kampe\TelegramTwoFactor\ErrorCode;
use Kampe\TelegramTwoFactor\Webhook\WebhookVerifier;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rejects anything on the webhook route that did not come from Telegram.
 *
 * Applied by the package's own route. If you register the route yourself, this
 * middleware is not optional — see Webhook\WebhookVerifier for what an
 * unauthenticated webhook lets a stranger do.
 *
 * Note the route must also be exempt from CSRF protection, since Telegram has no
 * session and no token. Exempting it is safe precisely because this middleware
 * authenticates the request by its secret token instead.
 */
final class VerifyTelegramWebhook
{
    public function __construct(private readonly WebhookVerifier $verifier)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $accepted = $this->verifier->accepts(
            $request->header('X-Telegram-Bot-Api-Secret-Token'),
            $request->ip(),
        );

        if (! $accepted) {
            // 403 with nothing in the body. Telegram will not retry a 403, and
            // a forger learns nothing about why it failed.
            return response()->json(
                ['ok' => false, 'error' => ErrorCode::WebhookUnauthorized->value],
                403
            );
        }

        return $next($request);
    }
}
