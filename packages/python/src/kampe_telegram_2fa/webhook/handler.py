"""Turning a verified Telegram update into protocol actions.

Framework-free: hand it a parsed update and it does the work. Routing, body
parsing and the secret-token check belong to the caller - see WebhookVerifier.

Commands: /start (with or without a deeplink payload), /code, /status, /link,
/unlink, /help. Anything else gets a short reply rather than silence, because
silence from a security bot reads as a broken security bot.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from ..config import Config
from ..contracts import (
    Clock,
    CodeStore,
    Logger,
    Messages,
    NullLogger,
    SystemClock,
    TelegramClient,
    is_verified,
)
from ..errors import ErrorCode
from ..service import TelegramTwoFactor

_WHITESPACE = re.compile(r"\s+")


class UpdateHandler:
    def __init__(
        self,
        tfa: TelegramTwoFactor,
        config: Config,
        store: CodeStore,
        telegram: TelegramClient,
        messages: Messages,
        logger: Logger | None = None,
        clock: Clock | None = None,
        account_label: Callable[[str], str] | None = None,
    ) -> None:
        self._tfa = tfa
        self._config = config
        self._store = store
        self._telegram = telegram
        self._messages = messages
        self._logger = logger or NullLogger()
        self._clock = clock or SystemClock()
        self._account_label = account_label
        self._extra: dict[str, Callable[[str, str], None]] = {}

    def on(self, command: str, handler: Callable[[str, str], None]) -> "UpdateHandler":
        """Register an application command, for example /balance.

        The handler runs only after the update has been verified as coming from
        Telegram, but the argument is still user input: treat it as such.
        """
        self._extra[command.lstrip("/").lower()] = handler

        return self

    def handle(self, update: dict[str, Any]) -> bool:
        """Handle one update.

        Returns whether the update was acted on. Either way the caller should
        answer 200: a non-2xx makes Telegram retry and queue every later update
        behind this one.
        """
        claim = self._claim(update)

        if claim is False:
            return False

        try:
            handled = self._dispatch(update)
        except Exception:
            # Release the claim so Telegram's retry is processed rather than
            # discarded as a duplicate. Marking an update done before its work
            # succeeds turns one transient failure into a permanently lost
            # operation.
            if claim is not None:
                self._store.forget(claim)

            raise

        # Only now is it really handled, so hold the claim for the full window.
        if claim is not None:
            self._store.put(claim, "done", self._config.update_dedupe_ttl)

        return handled

    def _dispatch(self, update: dict[str, Any]) -> bool:
        if "callback_query" in update:
            return self._handle_callback(update["callback_query"])

        message = update.get("message")

        if not isinstance(message, dict):
            return False

        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        text = message.get("text")

        if chat_id is None or not isinstance(text, str):
            return False

        chat_id = str(chat_id)
        text = text.strip()

        if text == "":
            return False

        # Private chats only. A bot added to a group would otherwise hand out
        # verification codes in front of every member of it.
        if chat.get("type", "private") != "private":
            return False

        if not text.startswith("/"):
            # Codes travel application-to-user, never user-to-bot, so free text
            # is not a code to check. Nudging rather than parsing also means a
            # user who pastes a code into the wrong window has not handed it to
            # the bot.
            self._telegram.send_message(chat_id, self._messages.unknown_command())

            return False

        command, argument = self._parse_command(text)

        self._logger.info(
            "telegram-2fa: command",
            {"command": command, "update_id": update.get("update_id")},
        )

        if command == "start":
            return self._start(chat_id, argument)

        if command in ("code", "otp", "2fa"):
            return self._code(chat_id)

        if command == "status":
            return self._status(chat_id)

        if command == "link":
            return self._link(chat_id)

        if command == "unlink":
            return self._unlink_hint(chat_id)

        if command == "help":
            return self._help(chat_id)

        return self._dispatch_extra(command, chat_id, argument)

    # ------------------------------------------------------------ commands

    def _start(self, chat_id: str, payload: str) -> bool:
        if payload == "":
            return self._help(chat_id)

        result = self._tfa.complete_deep_link(payload, chat_id)

        if result.ok and result.identity is not None:
            label = (
                self._account_label(result.identity.user_id)
                if self._account_label is not None
                else "your account"
            )

            self._telegram.send_message(
                chat_id, self._messages.link_succeeded(label, self._config.app_name)
            )

            return True

        self._telegram.send_message(
            chat_id,
            self._messages.already_linked()
            if result.error == ErrorCode.ALREADY_LINKED
            else self._messages.link_token_invalid(),
        )

        return False

    def _link(self, chat_id: str) -> bool:
        if is_verified(self._tfa.identity_for_chat(chat_id)):
            self._telegram.send_message(chat_id, self._messages.already_linked())

            return False

        request = self._tfa.start_paste_link(chat_id)

        self._telegram.send_message(
            chat_id,
            self._messages.link_instructions(
                request.token, self._config.link_ttl, self._config.app_name
            ),
        )

        return True

    def _code(self, chat_id: str) -> bool:
        # pull() sends the code itself, so the plaintext never reaches here.
        result = self._tfa.pull(chat_id)

        if result.ok:
            return True

        if result.error == ErrorCode.NOT_LINKED:
            text = self._messages.not_linked(self._config.app_name)
        elif result.error == ErrorCode.COOLDOWN:
            text = self._messages.cooldown(result.retry_after(self._clock.now()))
        else:
            text = self._messages.unknown_command()

        self._telegram.send_message(chat_id, text)

        return False

    def _status(self, chat_id: str) -> bool:
        linked = is_verified(self._tfa.identity_for_chat(chat_id))

        self._telegram.send_message(
            chat_id,
            self._messages.welcome(True, self._config.app_name)
            if linked
            else self._messages.not_linked(self._config.app_name),
        )

        return True

    def _unlink_hint(self, chat_id: str) -> bool:
        """/unlink explains where to do it, and does not do it.

        Whoever holds the phone can already read the codes; letting them also
        remove the factor with no session and no password turns a stolen phone
        into a permanently single-factor account.
        """
        if not is_verified(self._tfa.identity_for_chat(chat_id)):
            self._telegram.send_message(
                chat_id, self._messages.not_linked(self._config.app_name)
            )

            return False

        self._telegram.send_message(
            chat_id, self._messages.unlink_instructions(self._config.app_name)
        )

        return True

    def _help(self, chat_id: str) -> bool:
        linked = is_verified(self._tfa.identity_for_chat(chat_id))

        self._telegram.send_message(
            chat_id, self._messages.welcome(linked, self._config.app_name)
        )

        return True

    def _dispatch_extra(self, command: str, chat_id: str, argument: str) -> bool:
        handler = self._extra.get(command)

        if handler is None:
            self._telegram.send_message(chat_id, self._messages.unknown_command())

            return False

        handler(chat_id, argument)

        return True

    # ------------------------------------------------------------ plumbing

    def _handle_callback(self, callback_query: dict[str, Any]) -> bool:
        query_id = str(callback_query.get("id", ""))
        data = str(callback_query.get("data", ""))
        chat = (callback_query.get("message") or {}).get("chat") or {}
        chat_id = chat.get("id")

        if query_id != "":
            # Acknowledge first, or the user's client spins for ten seconds.
            self._telegram.answer_callback_query(query_id)

        if chat_id is None:
            return False

        chat_id = str(chat_id)

        if data == "code":
            return self._code(chat_id)

        if data == "status":
            return self._status(chat_id)

        if data == "link":
            return self._link(chat_id)

        if data == "help":
            return self._help(chat_id)

        return False

    @staticmethod
    def _parse_command(text: str) -> tuple[str, str]:
        parts = _WHITESPACE.split(text, maxsplit=1)
        command = parts[0].lstrip("/").lower()

        # In groups Telegram appends the bot name: /code@kampe_bot.
        if "@" in command:
            command = command.split("@", 1)[0]

        return command, (parts[1].strip() if len(parts) > 1 else "")

    def _claim(self, update: dict[str, Any]) -> str | bool | None:
        """Claim an update, so exactly one attempt processes it.

        Telegram retries an update it believes was not delivered, and delivers
        concurrently, so the same update_id can arrive more than once and at
        the same time. ``add`` is the whole mechanism: checking for a marker
        and then writing one is two operations, and two simultaneous
        deliveries both find nothing and both proceed.
        """
        if not self._config.dedupe_updates:
            return None

        update_id = update.get("update_id")

        if update_id is None:
            return None

        key = self._config.key("update", str(update_id))

        # A short claim, not the full window: if this process dies mid-handling
        # the claim lapses on its own and a later retry can pick the update up.
        ttl = max(30, min(120, self._config.update_dedupe_ttl))

        if not self._store.add(key, "claimed", ttl):
            self._logger.info(
                "telegram-2fa: duplicate update dropped", {"update_id": update_id}
            )

            return False

        return key
