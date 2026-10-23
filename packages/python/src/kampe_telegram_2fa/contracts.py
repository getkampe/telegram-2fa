"""Everything the library needs from the outside world.

All four protocols are small on purpose: an integration is four adapters, each
a handful of lines, rather than a framework to adopt.

This port is synchronous. Django, Flask and any WSGI stack call it directly;
from asyncio, wrap it with ``asyncio.to_thread`` or Starlette's
``run_in_threadpool``. Synchronous was chosen deliberately: in an event loop an
``await`` inside a critical section is a suspension point, and the Node port
shipped a bug of exactly that shape — ``take()`` awaited its read before
deleting, so two concurrent verifications of one code both succeeded. A
threading lock has no such trap, and it lets the tests spawn real threads,
which is a stronger check than interleaving a single loop by hand.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

#: Expectation meaning "whatever is there now", for recovery paths.
ANY_GENERATION = "\0any"


@dataclass(frozen=True)
class Identity:
    """An account's Telegram enrollment, as the identity store holds it.

    This represents the row rather than only the linked state, so an account
    that has been unlinked still has an Identity - carrying no chat, but
    carrying the generation. That is deliberate: revocation has to outlive the
    binding it revokes, or a token minted before an unlink would come back to
    life when the user links again.
    """

    user_id: str
    chat_id: str | None = None
    linked_at: int | None = None
    generation: str | None = None

    def is_verified(self) -> bool:
        """Only a verified link counts as a second factor.

        A row carrying a chat id with no verification timestamp is a link that
        was started and never completed. Treating it as linked would let anyone
        who can write a chat id into the row satisfy a challenge.
        """
        return self.chat_id is not None and self.linked_at is not None


def is_verified(identity: Identity | None) -> bool:
    return identity is not None and identity.is_verified()


@runtime_checkable
class CodeStore(Protocol):
    """Short-lived key/value storage with a TTL.

    Redis, Memcached, a table with an expires_at column - anything with expiry.
    It holds code hashes, never plaintext codes.

    ``take`` and ``add`` must be atomic. They are not a convenience: a
    verification built from get-check-delete is a time-of-check-to-time-of-use
    race, and two requests arriving together both read the live record, both
    match it, and both succeed - so a single-use code is used twice, and the
    attempt counter loses increments to the same lost-update race.

    A note on types: a store is not obliged to hand back exactly the type it
    was given. The PHP port's Redis adapter returns a bare numeric as a numeric
    string, because Laravel leaves such values unserialised so ``INCR`` still
    works on them. Callers must coerce rather than compare a stored numeric
    strictly; the cooldown read does.
    """

    def get(self, key: str) -> Any | None: ...

    def put(self, key: str, value: Any, ttl_seconds: int) -> None: ...

    def forget(self, key: str) -> None: ...

    def take(self, key: str) -> Any | None:
        """Atomically read a value and remove it, returning None when absent.

        Exactly one caller may receive a given value. Redis has GETDEL or EVAL;
        a SQL store can DELETE ... RETURNING.
        """
        ...

    def add(self, key: str, value: Any, ttl_seconds: int) -> bool:
        """Atomically write only if the key is absent; report whether it did.

        The boolean is the point: it makes the write a reservation exactly one
        caller can win, which is how the cooldown and the webhook's idempotency
        claim avoid check-then-write races.
        """
        ...


@runtime_checkable
class IdentityStore(Protocol):
    """Durable storage of the enrollment.

    Two rules the implementation, not the caller, has to guarantee:

    1. **Chat uniqueness at the storage layer** - a unique index, not only an
       application check, because two concurrent links both pass a check and
       only one can pass an index.
    2. **Transitions are conditional.** Every change goes through
       ``transition``, which compares the stored generation and writes in one
       operation. Read-then-write cannot express this: a recovery landing
       between a caller's validation and its write would be silently
       overwritten, which is how a replacement token outlives the enrollment it
       proved.
    """

    def find_by_user_id(self, user_id: str) -> Identity | None: ...

    def find_by_chat_id(self, chat_id: str) -> Identity | None: ...

    def transition(
        self,
        user_id: str,
        chat_id: str | None,
        expected: str | None,
        next_generation: str,
    ) -> Identity | None:
        """Compare-and-set the enrollment.

        ``expected`` is the generation the caller believes is current; None
        means "none recorded yet"; ANY_GENERATION skips the check.

        Returns the new state, or None when the expectation did not hold - in
        which case the stored row must be left exactly as it was.

        Raises ChatAlreadyLinked when the chat belongs to another account.
        """
        ...


@runtime_checkable
class TelegramClient(Protocol):
    """The slice of the Telegram Bot API this library needs."""

    def send_message(
        self,
        chat_id: str,
        text: str,
        inline_keyboard: list[list[dict[str, str]]] | None = None,
    ) -> bool: ...

    def answer_callback_query(self, callback_query_id: str, text: str | None = None) -> bool: ...

    def get_me(self) -> dict[str, Any]: ...

    def set_webhook(
        self, url: str, secret_token: str, allowed_updates: list[str] | None = None
    ) -> bool: ...

    def delete_webhook(self) -> bool: ...


@runtime_checkable
class Messages(Protocol):
    """Every piece of text the bot sends.

    All strings are sent with parse_mode HTML, so an implementation that
    interpolates user-supplied text must escape it - see
    ``telegram.messages.escape_html``.
    """

    def code(self, code: str, ttl_seconds: int) -> str: ...

    def link_instructions(self, code: str, ttl_seconds: int, app_name: str) -> str: ...

    def link_succeeded(self, account_label: str, app_name: str) -> str: ...

    def link_token_invalid(self) -> str: ...

    def already_linked(self) -> str: ...

    def not_linked(self, app_name: str) -> str: ...

    def cooldown(self, seconds_remaining: int) -> str: ...

    def unlink_instructions(self, app_name: str) -> str: ...

    def unlinked(self, app_name: str) -> str: ...

    def welcome(self, is_linked: bool, app_name: str) -> str: ...

    def unknown_command(self) -> str: ...


class Clock(Protocol):
    """Wall clock, injectable so expiry and cooldown are testable."""

    def now(self) -> int: ...


class SystemClock:
    def now(self) -> int:
        return int(time.time())


class FrozenClock:
    """A clock that moves only when you move it.

    Shipped in the package rather than the tests so applications can test
    their own expiry handling without sleeping through it.
    """

    def __init__(self, now: int = 1_700_000_000) -> None:
        self._now = now

    def now(self) -> int:
        return self._now

    def advance(self, seconds: int) -> "FrozenClock":
        self._now += seconds
        return self

    def set_to(self, timestamp: int) -> "FrozenClock":
        self._now = timestamp
        return self


class Logger(Protocol):
    """A narrow logging surface.

    Nothing passed to it contains a code, a link token or a raw update body -
    and the update body is the important one, because for this bot the update
    body *is* the code.
    """

    def info(self, message: str, context: dict[str, Any] | None = None) -> None: ...

    def warning(self, message: str, context: dict[str, Any] | None = None) -> None: ...

    def error(self, message: str, context: dict[str, Any] | None = None) -> None: ...


class NullLogger:
    """Discards everything. The default, so the library never writes to a log
    the host application did not hand it."""

    def info(self, message: str, context: dict[str, Any] | None = None) -> None:
        pass

    def warning(self, message: str, context: dict[str, Any] | None = None) -> None:
        pass

    def error(self, message: str, context: dict[str, Any] | None = None) -> None:
        pass


class StdlibLogger:
    """Adapts a :mod:`logging` logger."""

    def __init__(self, logger: Any) -> None:
        self._logger = logger

    def info(self, message: str, context: dict[str, Any] | None = None) -> None:
        self._logger.info(message, extra={"context": context or {}})

    def warning(self, message: str, context: dict[str, Any] | None = None) -> None:
        self._logger.warning(message, extra={"context": context or {}})

    def error(self, message: str, context: dict[str, Any] | None = None) -> None:
        self._logger.error(message, extra={"context": context or {}})
