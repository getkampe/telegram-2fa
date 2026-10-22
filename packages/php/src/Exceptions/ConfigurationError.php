<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Exceptions;

/**
 * The configuration cannot produce a secure installation.
 *
 * Thrown at construction time, never mid-request.
 */
final class ConfigurationError extends TelegramTwoFactorException
{
}
