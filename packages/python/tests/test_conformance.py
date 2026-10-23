"""SPEC.md section 9, against the shared fixture in /conformance.

The README says the implementations can run against one bot and one store. That
is a claim about field names and hash construction, and it only means anything
if every implementation reads the same committed records. The PHP and Node
packages once shipped snake_case and camelCase respectively, each agreed with
itself, and neither could have read the other.

The digests in the fixture are literals rather than values any implementation
recomputes, because a shared mistake would agree with itself.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from kampe_telegram_2fa import (
    Config,
    DefaultMessages,
    FrozenClock,
    MemoryCodeStore,
    MemoryIdentityStore,
    TelegramTwoFactor,
)

from .support import FakeTelegramClient

_FIXTURE = json.loads(
    (Path(__file__).resolve().parents[3] / "conformance" / "records.json").read_text(
        encoding="utf-8"
    )
)


class ConformanceTest(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        self.clock = FrozenClock(_FIXTURE["now"])
        self.store = MemoryCodeStore(self.clock)
        self.identities = MemoryIdentityStore(self.clock)
        self.telegram = FakeTelegramClient()
        self.config = Config(
            bot_token="123456789:AAFakeTokenForTestsOnly_0123456789abc",
            webhook_secret="s" * 48,
            bot_username="kampe_test_bot",
            key_prefix=_FIXTURE["config"]["key_prefix"],
            hash_algorithm=_FIXTURE["config"]["hash_algorithm"],
            hash_pepper=_FIXTURE["config"]["hash_pepper"],
        )
        self.tfa = TelegramTwoFactor(
            config=self.config,
            store=self.store,
            identities=self.identities,
            telegram=self.telegram,
            messages=DefaultMessages(),
            clock=self.clock,
        )

    def test_a_challenge_record_written_elsewhere_verifies_here(self) -> None:
        record = _FIXTURE["code_record"]

        # Seed the exact enrollment the fixture's challenge belongs to: a
        # challenge from a superseded enrollment is refused, so interop depends
        # on agreeing about that field too.
        self.identities.seed(record["user_id"], "555000111", record["enrollment"])
        self.store.put(record["key"], record["value"], 300)

        self.assertTrue(
            self.tfa.verify(
                record["user_id"], record["plaintext_code"], "withdrawal"
            ).ok,
            "a record in the shared wire format must verify through the public API",
        )

    def test_a_challenge_record_written_here_matches_the_wire_format(self) -> None:
        self.identities.seed("user-1", "555000111", "gen-local")
        self.tfa.push("user-1", "withdrawal")

        written = self.store.get(_FIXTURE["code_record"]["key"])

        self.assertIsInstance(written, dict)
        self.assertEqual(
            sorted(_FIXTURE["code_record"]["value"].keys()),
            sorted(written.keys()),
            "field names are the wire format of SPEC.md section 9",
        )

    def test_the_key_layout_matches_the_specification(self) -> None:
        self.identities.seed("user-1", "555000111", "gen-local")
        self.tfa.push("user-1", "withdrawal")

        self.assertIsNotNone(self.store.get(_FIXTURE["code_record"]["key"]))
        self.assertIsNotNone(self.store.get(_FIXTURE["cooldown_record"]["key"]))

    def test_an_on_demand_record_from_elsewhere_is_general_purpose(self) -> None:
        record = _FIXTURE["on_demand_record"]

        self.identities.seed(record["user_id"], "777000222", record["enrollment"])
        self.store.put(record["key"], record["value"], 300)

        self.assertTrue(
            self.tfa.verify(record["user_id"], record["plaintext_code"], "login").ok
        )

    def test_a_deeplink_record_written_elsewhere_resolves_here(self) -> None:
        record = _FIXTURE["deeplink_record"]

        self.store.put(record["key"], record["value"], 600)

        result = self.tfa.complete_deep_link(record["token"], "888000333")

        self.assertTrue(result.ok)
        self.assertEqual("888000333", self.tfa.identity(record["user_id"]).chat_id)

    def test_a_paste_record_written_elsewhere_resolves_here(self) -> None:
        record = _FIXTURE["paste_record"]

        self.store.put(record["key"], record["value"], 600)

        result = self.tfa.complete_paste_link("user-9", record["token"])

        self.assertTrue(result.ok)
        self.assertEqual(record["chat_id"], self.tfa.identity("user-9").chat_id)

    def test_the_cooldown_record_is_a_bare_integer(self) -> None:
        self.identities.seed("user-1", "555000111", "gen-local")
        self.tfa.push("user-1")

        written = self.store.get(_FIXTURE["cooldown_record"]["key"])

        # Not an object: the other implementations read this as a number.
        self.assertIsInstance(written, int)
        self.assertEqual(_FIXTURE["cooldown_record"]["value"], written)

    def test_a_cooldown_returned_as_a_string_is_still_understood(self) -> None:
        """A store may hand back a numeric string rather than an int.

        Laravel's Redis cache does exactly that, because it leaves bare
        numerics unserialised so INCR still works on them. This port must cope
        with a record another implementation wrote through such a store.
        """
        from kampe_telegram_2fa import ErrorCode

        self.identities.seed("user-1", "555000111", "gen-local")
        self.tfa.push("user-1")

        key = self.config.key("cooldown", "user-1")
        self.store.put(key, str(self.store.get(key)), 120)

        result = self.tfa.push("user-1")

        self.assertEqual(ErrorCode.COOLDOWN, result.error)
        self.assertIsInstance(result.next_send_at, int)


if __name__ == "__main__":
    unittest.main()
