"""The default Telegram client: urllib, no third-party dependencies."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from ..contracts import Logger, NullLogger
from ..errors import TelegramRequestFailed

_BASE = "https://api.telegram.org/bot"


class HttpTelegramClient:
    """Substitute your own implementation of the TelegramClient protocol to
    route through ``requests``, ``httpx``, a queue, or an existing bot library.
    """

    def __init__(
        self,
        bot_token: str,
        timeout_seconds: int = 10,
        logger: Logger | None = None,
        parse_mode: str = "HTML",
    ) -> None:
        self._bot_token = bot_token
        self._timeout = timeout_seconds
        self._logger = logger or NullLogger()
        self._parse_mode = parse_mode
        # Explicit, because a bot token travelling over an unverified
        # connection is a bot token handed to whoever is in the middle of it.
        # urllib verifies by default; this makes that a decision rather than a
        # default someone can switch off elsewhere.
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = True
        self._ssl_context.verify_mode = ssl.CERT_REQUIRED

    def send_message(
        self,
        chat_id: str,
        text: str,
        inline_keyboard: list[list[dict[str, str]]] | None = None,
    ) -> bool:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": self._parse_mode,
            "disable_web_page_preview": True,
        }

        if inline_keyboard is not None:
            payload["reply_markup"] = {"inline_keyboard": inline_keyboard}

        try:
            self._call("sendMessage", payload)

            return True
        except TelegramRequestFailed as error:
            # Delivery is fallible and the caller has a fallback path, so this
            # is reported rather than raised. The message body is never logged:
            # for a challenge, the body is the code.
            self._logger.error(
                "telegram-2fa: sendMessage failed", {"reason": str(error)}
            )

            return False

    def answer_callback_query(self, callback_query_id: str, text: str | None = None) -> bool:
        payload: dict[str, Any] = {"callback_query_id": callback_query_id}

        if text is not None:
            payload["text"] = text

        try:
            self._call("answerCallbackQuery", payload)

            return True
        except TelegramRequestFailed:
            return False

    def get_me(self) -> dict[str, Any]:
        result = self._call("getMe", {})

        return result if isinstance(result, dict) else {}

    def set_webhook(
        self, url: str, secret_token: str, allowed_updates: list[str] | None = None
    ) -> bool:
        if not url.startswith("https://"):
            raise TelegramRequestFailed(
                "Telegram will only deliver webhooks to an https URL with a valid "
                "certificate."
            )

        self._call(
            "setWebhook",
            {
                "url": url,
                "secret_token": secret_token,
                "allowed_updates": allowed_updates or ["message", "callback_query"],
                # Telegram queues updates while a webhook is unset or failing.
                # On a first deploy that queue can hold stale /code requests,
                # so it is dropped rather than replayed into a live 2FA flow.
                "drop_pending_updates": True,
            },
        )

        return True

    def delete_webhook(self) -> bool:
        self._call("deleteWebhook", {"drop_pending_updates": True})

        return True

    def _call(self, method: str, payload: dict[str, Any]) -> Any:
        request = urllib.request.Request(
            f"{_BASE}{self._bot_token}/{method}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout, context=self._ssl_context
            ) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            # Telegram puts its own description in the body of a 4xx, and that
            # description does not echo the message back, so it is safe to
            # surface.
            try:
                body = json.loads(error.read().decode("utf-8"))
            except (ValueError, OSError):
                raise TelegramRequestFailed(
                    f"Telegram rejected {method} with status {error.code}."
                ) from error

            raise TelegramRequestFailed(
                f"Telegram rejected {method} with status {error.code}: "
                f"{body.get('description', 'no description')}"
            ) from error
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise TelegramRequestFailed(
                f"Telegram could not be reached: {error}"
            ) from error

        if body.get("ok") is not True:
            raise TelegramRequestFailed(
                f"Telegram rejected {method}: {body.get('description', 'no description')}"
            )

        return body.get("result", True)
