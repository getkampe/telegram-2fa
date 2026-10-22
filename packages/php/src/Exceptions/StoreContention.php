<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Exceptions;

/**
 * A store mutation could not take the lock that makes it safe.
 *
 * Raised rather than skipped. A silently dropped write would mean a challenge
 * the application believes it issued and the user never receives, or a record
 * that outlives the revocation meant to remove it; an exception at least
 * surfaces that the store is too contended or its lock driver is broken.
 */
final class StoreContention extends TelegramTwoFactorException
{
}
