<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Contracts;

/**
 * A deliberately narrow logging surface, shaped as a subset of PSR-3 so that any
 * PSR-3 logger can be dropped in through Logging\PsrLogger.
 *
 * Nothing this library passes to a logger contains a code, a link token or a raw
 * Telegram update body. See SPEC.md sections 6 and 7.4: update bodies carry the
 * message text, and the message text is where the codes are.
 */
interface Logger
{
    /**
     * @param  array<string, mixed>  $context
     */
    public function info(string $message, array $context = []): void;

    /**
     * @param  array<string, mixed>  $context
     */
    public function warning(string $message, array $context = []): void;

    /**
     * @param  array<string, mixed>  $context
     */
    public function error(string $message, array $context = []): void;
}
