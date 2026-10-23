"""Return values of the protocol operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contracts import Identity
from .errors import ErrorCode


@dataclass(frozen=True)
class ChallengeResult:
    """The outcome of asking for a code to be issued and delivered.

    Note what is absent: the code. Neither challenge direction returns it,
    which is the only reason a result like this can be serialised straight
    into an HTTP response.
    """

    ok: bool
    error: ErrorCode | None = None
    expires_at: int | None = None
    next_send_at: int | None = None

    @classmethod
    def sent(cls, expires_at: int, next_send_at: int) -> "ChallengeResult":
        return cls(True, None, expires_at, next_send_at)

    @classmethod
    def failed(cls, error: ErrorCode, next_send_at: int | None = None) -> "ChallengeResult":
        return cls(False, error, None, next_send_at)

    def retry_after(self, now: int) -> int:
        """Seconds to wait before offering a resend, never negative."""
        if self.next_send_at is None:
            return 0

        return max(0, self.next_send_at - now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "error": self.error.value if self.error else None,
            "expires_at": self.expires_at,
            "next_send_at": self.next_send_at,
        }


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of checking a submitted code."""

    ok: bool
    error: ErrorCode | None = None
    attempts_remaining: int | None = None

    @classmethod
    def passed(cls) -> "VerificationResult":
        return cls(True)

    @classmethod
    def failed(
        cls, error: ErrorCode, attempts_remaining: int | None = None
    ) -> "VerificationResult":
        return cls(False, error, attempts_remaining)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "error": self.error.value if self.error else None,
            "attempts_remaining": self.attempts_remaining,
        }


@dataclass(frozen=True)
class LinkRequest:
    """A pending link, ready to be shown to the user.

    This is the one place a secret legitimately leaves the library, because the
    user has to receive it somehow. For the deeplink flow put ``url`` in a
    button or a QR code; for the paste flow show ``token`` in the chat. Either
    way it does not belong in a log line or an audit record.
    """

    token: str
    expires_at: int
    url: str | None = None


@dataclass(frozen=True)
class LinkResult:
    """The outcome of resolving a link token."""

    ok: bool
    identity: Identity | None = None
    error: ErrorCode | None = None

    @classmethod
    def linked(cls, identity: Identity) -> "LinkResult":
        return cls(True, identity, None)

    @classmethod
    def failed(cls, error: ErrorCode) -> "LinkResult":
        return cls(False, None, error)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "error": self.error.value if self.error else None,
            "linked_at": self.identity.linked_at if self.identity else None,
        }
