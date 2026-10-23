"""In-process stores, for tests and single-process scripts.

Not for production behind more than one process: each worker would hold its own
copy, so a code issued by one request would be invisible to the next. Use Redis,
or a table with an expires_at column.

**Why every mutation holds a lock.** Python's GIL does not make a
read-modify-write sequence atomic: the interpreter can switch threads between
any two bytecodes, so two threads can both read a record before either deletes
it — and then a single-use code is used twice and the attempt counter loses
increments. ``threading.RLock`` is what actually serialises them, and the tests
spawn real threads to prove it rather than interleaving a single one by hand.
"""

from __future__ import annotations

import threading
from typing import Any

from ..contracts import ANY_GENERATION, Clock, Identity, SystemClock
from ..errors import ChatAlreadyLinked


class MemoryCodeStore:
    def __init__(self, clock: Clock | None = None) -> None:
        self._clock = clock or SystemClock()
        self._items: dict[str, tuple[Any, int]] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            return self._read(key)

    def put(self, key: str, value: Any, ttl_seconds: int) -> None:
        with self._lock:
            self._items[key] = (value, self._clock.now() + ttl_seconds)

    def forget(self, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)

    def take(self, key: str) -> Any | None:
        # Read and delete inside one lock, so a second caller cannot observe
        # the value this one is removing.
        with self._lock:
            value = self._read(key)
            self._items.pop(key, None)

            return value

    def add(self, key: str, value: Any, ttl_seconds: int) -> bool:
        with self._lock:
            if self._read(key) is not None:
                return False

            self._items[key] = (value, self._clock.now() + ttl_seconds)

            return True

    def _read(self, key: str) -> Any | None:
        """Caller must hold the lock."""
        item = self._items.get(key)

        if item is None:
            return None

        value, expires_at = item

        if expires_at <= self._clock.now():
            self._items.pop(key, None)

            return None

        return value


class MemoryIdentityStore:
    """An in-memory identity store.

    It models both rules a real store must enforce: one chat belongs to one
    account, and a transition only applies when the stored generation is the one
    the caller expected. Rows survive unlinking, because the generation has to.
    """

    def __init__(self, clock: Clock | None = None) -> None:
        self._clock = clock or SystemClock()
        self._rows: dict[str, Identity] = {}
        self._lock = threading.RLock()

    def find_by_user_id(self, user_id: str) -> Identity | None:
        with self._lock:
            return self._rows.get(user_id)

    def find_by_chat_id(self, chat_id: str) -> Identity | None:
        with self._lock:
            return self._find_by_chat_id(chat_id)

    def transition(
        self,
        user_id: str,
        chat_id: str | None,
        expected: str | None,
        next_generation: str,
    ) -> Identity | None:
        with self._lock:
            current = self._rows.get(user_id)

            if expected != ANY_GENERATION and (
                current.generation if current else None
            ) != expected:
                # The expectation failed, so the stored row is left exactly as
                # it was. Returning None rather than raising lets the caller
                # decide whether this is a conflict or a stale token.
                return None

            if chat_id is not None:
                holder = self._find_by_chat_id(chat_id)

                if holder is not None and holder.user_id != user_id:
                    raise ChatAlreadyLinked(
                        "That Telegram chat is already the second factor for "
                        "another account."
                    )

            identity = Identity(
                user_id=user_id,
                chat_id=chat_id,
                linked_at=None if chat_id is None else self._clock.now(),
                generation=next_generation,
            )

            self._rows[user_id] = identity

            return identity

    def seed(self, user_id: str, chat_id: str, generation: str) -> Identity:
        """Test helper: seed a verified enrollment without going through a flow."""
        with self._lock:
            identity = Identity(user_id, chat_id, self._clock.now(), generation)
            self._rows[user_id] = identity

            return identity

    def _find_by_chat_id(self, chat_id: str) -> Identity | None:
        """Caller must hold the lock."""
        for identity in self._rows.values():
            if identity.chat_id is not None and identity.chat_id == chat_id:
                return identity

        return None
