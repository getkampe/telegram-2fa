"""Shared harness for the test suite."""

from __future__ import annotations

import re
import unittest
from typing import Any

from kampe_telegram_2fa import (
    Config,
    DefaultMessages,
    FrozenClock,
    Identity,
    MemoryCodeStore,
    MemoryIdentityStore,
    TelegramTwoFactor,
)

_CODE = re.compile(r"<code>([^<]+)</code>")


class FakeTelegramClient:
    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []
        self.answered_callbacks: list[str] = []
        self.should_fail_sending = False
        self._during_next_failure: Any = None

    def fail_next_send(self, during: Any) -> None:
        """Fail the next send, running ``during`` while it is "in flight".

        Models a send that blocks long enough for the world to move on - the
        cooldown lapsing and another challenge being issued - before the
        failure is reported and its cleanup runs.
        """
        self.should_fail_sending = True
        self._during_next_failure = during

    def send_message(
        self, chat_id: str, text: str, inline_keyboard: Any = None
    ) -> bool:
        if self.should_fail_sending:
            if self._during_next_failure is not None:
                # One-shot: the hook models a single slow, failing send, and
                # the sends it triggers must succeed.
                during = self._during_next_failure
                self._during_next_failure = None
                self.should_fail_sending = False
                during()

            return False

        self.sent.append({"chat_id": chat_id, "text": text})

        return True

    def answer_callback_query(self, callback_query_id: str, text: str | None = None) -> bool:
        self.answered_callbacks.append(callback_query_id)

        return True

    def get_me(self) -> dict[str, Any]:
        return {"id": 1, "username": "kampe_test_bot", "first_name": "Kampe"}

    def set_webhook(self, *args: Any, **kwargs: Any) -> bool:
        return True

    def delete_webhook(self) -> bool:
        return True

    def last_message(self) -> str:
        return self.sent[-1]["text"] if self.sent else ""

    def last_sent_to(self) -> str | None:
        return self.sent[-1]["chat_id"] if self.sent else None

    def reset(self) -> None:
        self.sent = []
        self.answered_callbacks = []


def make_config(**overrides: Any) -> Config:
    defaults: dict[str, Any] = {
        "bot_token": "123456789:AAFakeTokenForTestsOnly_0123456789abc",
        "webhook_secret": "s" * 48,
        "hash_pepper": "p" * 48,
        "bot_username": "kampe_test_bot",
        "app_name": "Kampe",
    }
    defaults.update(overrides)

    return Config(**defaults)


class Harness(unittest.TestCase):
    """A fully wired instance on in-memory parts."""

    def setUp(self) -> None:
        super().setUp()

        self.clock = FrozenClock()
        self.store = MemoryCodeStore(self.clock)
        self.identities = MemoryIdentityStore(self.clock)
        self.telegram = FakeTelegramClient()
        self.config = make_config()
        self.messages = DefaultMessages()

        self.tfa = TelegramTwoFactor(
            config=self.config,
            store=self.store,
            identities=self.identities,
            telegram=self.telegram,
            messages=self.messages,
            clock=self.clock,
        )

    def with_config(self, **overrides: Any) -> TelegramTwoFactor:
        """A service wired to the same parts but a different configuration."""
        return TelegramTwoFactor(
            config=make_config(**overrides),
            store=self.store,
            identities=self.identities,
            telegram=self.telegram,
            messages=self.messages,
            clock=self.clock,
        )

    def seed(self, user_id: str = "user-1", chat_id: str = "555000111") -> Identity:
        """Seed a verified enrollment without going through a link flow."""
        return self.identities.seed(user_id, chat_id, f"gen-{user_id}")

    def last_code(self) -> str:
        """The code from the most recent outgoing message.

        Tests have to recover the code from the message because the library
        deliberately never returns it.
        """
        match = _CODE.search(self.telegram.last_message())

        return match.group(1) if match else ""

    @staticmethod
    def wrong_code(code: str) -> str:
        return "111111" if code == "000000" else "000000"
