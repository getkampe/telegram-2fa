"""SPEC.md section 7 — webhook authentication, dispatch and idempotency."""

from __future__ import annotations

import unittest

from kampe_telegram_2fa import ConfigurationError, WebhookVerifier
from kampe_telegram_2fa.webhook.handler import UpdateHandler

from .support import Harness, make_config

SECRET = "s" * 48


class WebhookVerifierTest(unittest.TestCase):
    """The check that matters most: without it the webhook accepts a forged
    assertion that any chat id is asking for a code."""

    def test_the_matching_secret_is_accepted(self) -> None:
        self.assertTrue(WebhookVerifier(make_config()).accepts(SECRET))

    def test_a_wrong_secret_is_rejected(self) -> None:
        self.assertFalse(WebhookVerifier(make_config()).accepts("x" * 48))

    def test_a_missing_secret_is_rejected(self) -> None:
        verifier = WebhookVerifier(make_config())

        self.assertFalse(verifier.accepts(None))
        self.assertFalse(verifier.accepts(""))

    def test_a_prefix_or_extension_of_the_secret_is_rejected(self) -> None:
        verifier = WebhookVerifier(make_config())

        self.assertFalse(verifier.accepts("s" * 47))
        self.assertFalse(verifier.accepts("s" * 49))

    def test_ip_restriction_accepts_telegram_ranges(self) -> None:
        verifier = WebhookVerifier(make_config(restrict_webhook_ips=True))

        self.assertTrue(verifier.accepts(SECRET, "149.154.160.1"))
        self.assertTrue(verifier.accepts(SECRET, "149.154.175.254"))
        self.assertTrue(verifier.accepts(SECRET, "91.108.4.10"))

    def test_ip_restriction_rejects_everything_else(self) -> None:
        verifier = WebhookVerifier(make_config(restrict_webhook_ips=True))

        for address in ("8.8.8.8", "149.154.176.1", "127.0.0.1", None, "not-an-ip"):
            self.assertFalse(verifier.accepts(SECRET, address), address)

    def test_ip_restriction_is_off_by_default(self) -> None:
        # Off by default because behind a proxy the peer address is the proxy,
        # so the check would be either useless or actively misleading.
        self.assertTrue(WebhookVerifier(make_config()).accepts(SECRET, "8.8.8.8"))


class ConfigValidationTest(unittest.TestCase):
    def test_a_missing_or_short_webhook_secret_is_refused(self) -> None:
        for secret in ("", "x"):
            with self.assertRaises(ConfigurationError):
                make_config(webhook_secret=secret)

    def test_a_missing_or_short_pepper_is_refused(self) -> None:
        for pepper in ("", "too-short"):
            with self.assertRaises(ConfigurationError):
                make_config(hash_pepper=pepper)

    def test_a_malformed_bot_token_is_refused(self) -> None:
        with self.assertRaises(ConfigurationError):
            make_config(bot_token="not-a-token")

    def test_a_bot_username_with_an_at_sign_is_refused(self) -> None:
        with self.assertRaises(ConfigurationError):
            make_config(bot_username="@kampe_test_bot")

    def test_out_of_range_numbers_are_refused(self) -> None:
        for overrides in (
            {"max_attempts": 0},
            {"max_attempts": 1000},
            {"code_ttl": 86_400},
            {"cooldown": 0},
            {"link_code_length": 6},
            {"code_length": 4},
        ):
            with self.assertRaises(ConfigurationError, msg=str(overrides)):
                make_config(**overrides)

    def test_non_integers_are_refused(self) -> None:
        """A float reaches Redis as an EX argument, and ``bool`` is an ``int``
        subclass in Python, so ``max_attempts=True`` would otherwise pass as 1
        — accepted silently and almost certainly not what the caller meant."""
        for overrides in (
            {"code_ttl": 300.5},
            {"max_attempts": 2.5},
            {"max_attempts": True},
            {"code_ttl": "300"},
        ):
            with self.assertRaises(ConfigurationError, msg=str(overrides)):
                make_config(**overrides)

    def test_an_empty_on_demand_allowlist_is_refused(self) -> None:
        with self.assertRaises(ConfigurationError):
            make_config(on_demand_satisfies=[])

    def test_from_env_rejects_a_non_numeric_value(self) -> None:
        env = {
            "TELEGRAM_BOT_TOKEN": "123456789:AAFakeTokenForTestsOnly_0123456789abc",
            "TELEGRAM_WEBHOOK_SECRET": SECRET,
            "TELEGRAM_2FA_HASH_PEPPER": "p" * 48,
            "TELEGRAM_2FA_MAX_ATTEMPTS": "5 attempts",
        }

        with self.assertRaises(ConfigurationError):
            from kampe_telegram_2fa import Config

            Config.from_env(env)


class UpdateHandlerTest(Harness):
    def setUp(self) -> None:
        super().setUp()

        self.handler = UpdateHandler(
            tfa=self.tfa,
            config=self.config,
            store=self.store,
            telegram=self.telegram,
            messages=self.messages,
            clock=self.clock,
        )
        self._update_id = 1000

    def message(self, text: str, chat_id: str = "555000111") -> dict:
        self._update_id += 1

        return {
            "update_id": self._update_id,
            "message": {
                "message_id": 1,
                "text": text,
                "chat": {"id": chat_id, "type": "private"},
            },
        }

    def test_start_with_a_payload_links_the_account(self) -> None:
        request = self.tfa.start_deep_link("user-1")

        self.handler.handle(self.message(f"/start {request.token}"))

        self.assertTrue(self.tfa.is_linked("user-1"))
        self.assertIn("second factor", self.telegram.last_message())

    def test_start_without_a_payload_sends_the_welcome(self) -> None:
        self.handler.handle(self.message("/start"))

        self.assertIn("security bot", self.telegram.last_message())

    def test_code_issues_a_code_for_a_linked_chat(self) -> None:
        self.seed()

        self.handler.handle(self.message("/code"))

        self.assertRegex(self.last_code(), r"^\d{6}$")

    def test_code_tells_an_unlinked_chat_how_to_link(self) -> None:
        self.handler.handle(self.message("/code"))

        self.assertIn("not linked", self.telegram.last_message())

    def test_code_inside_the_cooldown_explains_the_wait(self) -> None:
        self.seed()

        self.handler.handle(self.message("/code"))
        self.handler.handle(self.message("/code"))

        self.assertIn("just sent", self.telegram.last_message())

    def test_a_repeated_update_id_is_dropped(self) -> None:
        self.seed()
        update = self.message("/code")

        self.assertTrue(self.handler.handle(update))
        self.assertFalse(self.handler.handle(update))
        self.assertEqual(1, len(self.telegram.sent))

    def test_the_claim_is_released_when_handling_fails(self) -> None:
        """An update marked done before its work succeeds is an update
        permanently lost: the retry arrives, sees the marker, and drops it."""
        self.seed()

        def boom(chat_id: str, argument: str) -> None:
            raise RuntimeError("downstream failure")

        self.handler.on("boom", boom)
        update = self.message("/boom")

        with self.assertRaises(RuntimeError):
            self.handler.handle(update)

        seen: list[bool] = []
        self.handler.on("boom", lambda chat_id, argument: seen.append(True))

        self.handler.handle(update)

        self.assertEqual([True], seen, "Telegram's retry must be processed")

    def test_group_chats_are_ignored(self) -> None:
        self.seed("user-1", "-1001234567890")

        update = self.message("/code", "-1001234567890")
        update["message"]["chat"]["type"] = "supergroup"

        self.handler.handle(update)

        # Otherwise the bot hands out codes in front of every member.
        self.assertEqual(0, len(self.telegram.sent))

    def test_free_text_is_not_treated_as_a_code(self) -> None:
        self.seed()

        self.handler.handle(self.message("123456"))

        self.assertIn("do not know that command", self.telegram.last_message())

    def test_a_command_addressed_to_the_bot_is_understood(self) -> None:
        self.seed()

        self.handler.handle(self.message("/code@kampe_test_bot"))

        self.assertRegex(self.last_code(), r"^\d{6}$")

    def test_unlink_answers_with_instructions_and_does_not_unlink(self) -> None:
        self.seed()

        self.handler.handle(self.message("/unlink"))

        self.assertIn("cannot be done from the chat", self.telegram.last_message())
        self.assertTrue(self.tfa.is_linked("user-1"))

    def test_an_unknown_command_gets_a_reply(self) -> None:
        self.handler.handle(self.message("/nonsense"))

        self.assertIn("do not know that command", self.telegram.last_message())

    def test_an_application_command_can_be_registered(self) -> None:
        seen: list[tuple[str, str]] = []
        self.handler.on("balance", lambda chat_id, argument: seen.append((chat_id, argument)))

        self.handler.handle(self.message("/balance usd"))

        self.assertEqual([("555000111", "usd")], seen)

    def test_a_callback_query_is_acknowledged_then_handled(self) -> None:
        self.seed()

        self.handler.handle(
            {
                "update_id": 991,
                "callback_query": {
                    "id": "cb-1",
                    "data": "code",
                    "message": {"chat": {"id": "555000111", "type": "private"}},
                },
            }
        )

        self.assertEqual(["cb-1"], self.telegram.answered_callbacks)
        self.assertRegex(self.last_code(), r"^\d{6}$")

    def test_an_update_with_no_message_is_ignored(self) -> None:
        self.assertFalse(self.handler.handle({"update_id": 1}))
        self.assertEqual(0, len(self.telegram.sent))


if __name__ == "__main__":
    unittest.main()
