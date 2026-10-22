<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Exceptions;

/**
 * Telegram refused a request, or could not be reached.
 *
 * Sending is treated as fallible everywhere in this library: a challenge whose
 * delivery failed returns send_failed rather than throwing, so the caller can
 * offer another factor. This exception is reserved for the calls whose result the
 * caller actually needs, such as getMe and setWebhook.
 */
final class TelegramRequestFailed extends TelegramTwoFactorException
{
}
