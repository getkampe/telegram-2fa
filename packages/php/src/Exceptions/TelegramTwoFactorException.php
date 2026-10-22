<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Exceptions;

use RuntimeException;

/**
 * Base class for every exception this library throws, so a host application can
 * catch the whole library with one clause.
 */
class TelegramTwoFactorException extends RuntimeException
{
}
