"""The error vocabulary of SPEC.md section 10, and the exceptions."""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    """Protocol error identifiers.

    The string values are the wire form, shared with every other
    implementation, so a client written against them works against any of
    them. Do not change the values.
    """

    NOT_LINKED = "not_linked"
    ALREADY_LINKED = "already_linked"
    COOLDOWN = "cooldown"
    SEND_FAILED = "send_failed"
    INVALID = "invalid"
    EXPIRED = "expired"
    TOO_MANY_ATTEMPTS = "too_many_attempts"
    INVALID_TOKEN = "invalid_token"
    WEBHOOK_UNAUTHORIZED = "webhook_unauthorized"

    def message(self) -> str:
        """Text safe to show an end user.

        Deliberately vague about which of "never issued", "expired" and
        "already used" applies, because distinguishing them tells an attacker
        holding a session whether a challenge is in flight.
        """
        return _MESSAGES[self]


_MESSAGES = {
    ErrorCode.NOT_LINKED: "No Telegram account is linked to this profile.",
    ErrorCode.ALREADY_LINKED: "This Telegram account is already linked.",
    ErrorCode.COOLDOWN: "A code was just sent. Please wait before requesting another.",
    ErrorCode.SEND_FAILED: (
        "The code could not be delivered. Please try again or use another method."
    ),
    ErrorCode.INVALID: "That code is not valid.",
    ErrorCode.EXPIRED: "That code is no longer valid. Request a new one.",
    ErrorCode.TOO_MANY_ATTEMPTS: "Too many incorrect attempts. Request a new code.",
    ErrorCode.INVALID_TOKEN: "This link has expired or has already been used.",
    ErrorCode.WEBHOOK_UNAUTHORIZED: "Unauthorized.",
}


class TelegramTwoFactorError(Exception):
    """Base class for every error this library raises."""


class ConfigurationError(TelegramTwoFactorError):
    """The configuration cannot produce a secure installation.

    Raised when the config is built, never mid-request.
    """


class TelegramRequestFailed(TelegramTwoFactorError):
    """Telegram refused a request, or could not be reached."""


class ChatAlreadyLinked(TelegramTwoFactorError):
    """A chat is already bound to a different account.

    Identity stores raise this rather than reassigning: one Telegram account
    acting as the second factor for several accounts means one compromised
    Telegram account compromises all of them.
    """
