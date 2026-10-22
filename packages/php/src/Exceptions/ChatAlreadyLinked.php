<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Exceptions;

/**
 * A chat is already bound to a different user.
 *
 * Identity stores throw this rather than reassigning. One Telegram account acting
 * as the second factor for several accounts means one compromised Telegram account
 * compromises all of them, so the binding is refused instead of moved.
 */
final class ChatAlreadyLinked extends TelegramTwoFactorException
{
}
