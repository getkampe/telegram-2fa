"""Validated configuration."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .codes import CodeGenerator
from .errors import ConfigurationError

_BOT_TOKEN = re.compile(r"^\d+:[A-Za-z0-9_-]{30,}$")
_WEBHOOK_SECRET = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
_BOT_USERNAME = re.compile(r"^[A-Za-z0-9_]{5,32}$")


@dataclass(frozen=True)
class Config:
    """Validated configuration.

    The constructor rejects a configuration that cannot be secure, rather than
    accepting it and logging a warning nobody reads. A missing webhook secret
    is the clearest case: with one absent, the webhook is an open endpoint that
    will mint a code for any chat id a stranger posts to it, and the
    application looks like it works. Failing at startup is the only version of
    that outcome anyone notices.
    """

    bot_token: str
    webhook_secret: str
    hash_pepper: str
    bot_username: str | None = None
    app_name: str = "Kampe"
    code_length: int = 6
    code_ttl: int = 300
    cooldown: int = 120
    max_attempts: int = 5
    link_code_length: int = 8
    link_ttl: int = 600
    key_prefix: str = "tg2fa"
    hash_algorithm: str = "sha256"
    dedupe_updates: bool = True
    update_dedupe_ttl: int = 3600
    restrict_webhook_ips: bool = False
    #: Which purposes a code the user fetched with /code may satisfy. None
    #: means any: an on-demand code is general-purpose because it cannot know
    #: what it is for and the user asked for it deliberately. An allowlist
    #: narrows that, at the cost of needing a push path for unlinking.
    on_demand_satisfies: Sequence[str] | None = field(default=None)

    def __post_init__(self) -> None:
        if not self.bot_token.strip():
            raise ConfigurationError(
                "A bot token is required. Create a bot with @BotFather and set "
                "TELEGRAM_BOT_TOKEN."
            )

        if not _BOT_TOKEN.match(self.bot_token):
            raise ConfigurationError(
                "The bot token is not in the format @BotFather issues "
                "(123456789:AA...). Check that the value was not truncated or quoted."
            )

        # Telegram accepts 1 to 256 characters here. One character would
        # satisfy Telegram and defeat the purpose, so the floor is ours.
        if not _WEBHOOK_SECRET.match(self.webhook_secret):
            raise ConfigurationError(
                "The webhook secret must be 32 to 256 characters of A-Z, a-z, 0-9, "
                "underscore or hyphen. Generate one with "
                "CodeGenerator().webhook_secret() and set TELEGRAM_WEBHOOK_SECRET. "
                "This is what stops a stranger forging updates against your "
                "webhook; it is not optional."
            )

        # Required, not recommended. A six-digit code has a million possible
        # values, so an unkeyed digest of one is reversed by a table anyone can
        # build in seconds: without a key, hashing the codes protects nothing
        # against someone who reads the store.
        if len(self.hash_pepper) < 32:
            raise ConfigurationError(
                "hash_pepper must be at least 32 characters. It is the HMAC key for "
                "code hashes, and without it a dumped cache of six-digit code hashes "
                "is reversed by a lookup table of a million entries. Generate one "
                "with CodeGenerator().webhook_secret() and set "
                "TELEGRAM_2FA_HASH_PEPPER. Keep it outside the store it protects."
            )

        if self.bot_username is not None and not _BOT_USERNAME.match(self.bot_username):
            raise ConfigurationError(
                "The bot username must be 5 to 32 characters of A-Z, a-z, 0-9 or "
                "underscore, with no leading @."
            )

        for name in (
            "code_length",
            "code_ttl",
            "cooldown",
            "max_attempts",
            "link_code_length",
            "link_ttl",
            "update_dedupe_ttl",
        ):
            self._require_whole_number(name, getattr(self, name))

        if not 6 <= self.code_length <= 8:
            raise ConfigurationError("code_length must be between 6 and 8.")

        if not 30 <= self.code_ttl <= 600:
            raise ConfigurationError(
                "code_ttl must be between 30 and 600 seconds. A code that outlives "
                "the step it authorises is a code sitting in a chat history waiting "
                "to be reused."
            )

        if self.cooldown < 30:
            raise ConfigurationError(
                "cooldown must be at least 30 seconds, or the bot becomes a way to "
                "spam someone via your bot token."
            )

        if not 1 <= self.max_attempts <= 10:
            raise ConfigurationError(
                "max_attempts must be between 1 and 10. Unlimited attempts against a "
                "six-digit code is not two-factor authentication."
            )

        if self.link_code_length < 8:
            raise ConfigurationError(
                "link_code_length must be at least 8. Paste-flow codes are stored "
                "under a key derived from the code, so they share one namespace "
                "across every user and a short code is enumerable."
            )

        if not 60 <= self.link_ttl <= 900:
            raise ConfigurationError("link_ttl must be between 60 and 900 seconds.")

        if self.hash_algorithm not in hashlib.algorithms_available:
            raise ConfigurationError(f'Unknown hash algorithm "{self.hash_algorithm}".')

        if not self.key_prefix or ":" in self.key_prefix:
            raise ConfigurationError(
                "key_prefix must be non-empty and must not contain a colon."
            )

        if self.on_demand_satisfies is not None:
            if len(self.on_demand_satisfies) == 0:
                raise ConfigurationError(
                    "on_demand_satisfies must list at least one purpose, or be None "
                    "for any. An empty list makes every code fetched with /code "
                    "useless."
                )

            for purpose in self.on_demand_satisfies:
                if not isinstance(purpose, str) or purpose == "":
                    raise ConfigurationError(
                        "on_demand_satisfies must contain non-empty strings."
                    )

    @staticmethod
    def _require_whole_number(name: str, value: object) -> None:
        """Reject anything that is not a whole number.

        ``bool`` is excluded explicitly because it is a subclass of ``int`` in
        Python, so ``max_attempts=True`` would otherwise pass as 1 — accepted
        silently, and almost certainly not what the caller meant. Floats are
        rejected because the value reaches Redis as an EX argument.
        """
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigurationError(
                f"{name} must be a whole number; received {value!r}."
            )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Config":
        """Build from environment variables, for the common case."""
        source = os.environ if env is None else env

        def number(key: str, fallback: int) -> int:
            raw = source.get(key, "")

            if raw == "":
                return fallback

            try:
                return int(raw)
            except ValueError as exc:
                # A float() here would accept "5 minutes" as nothing and NaN
                # as a value that passes every range check below it.
                raise ConfigurationError(
                    f"{key} must be a whole number; received {raw!r}."
                ) from exc

        return cls(
            bot_token=source.get("TELEGRAM_BOT_TOKEN", ""),
            webhook_secret=source.get("TELEGRAM_WEBHOOK_SECRET", ""),
            hash_pepper=source.get("TELEGRAM_2FA_HASH_PEPPER", ""),
            bot_username=source.get("TELEGRAM_BOT_USERNAME") or None,
            app_name=source.get("TELEGRAM_2FA_APP_NAME") or "Kampe",
            code_ttl=number("TELEGRAM_2FA_CODE_TTL", 300),
            cooldown=number("TELEGRAM_2FA_COOLDOWN", 120),
            max_attempts=number("TELEGRAM_2FA_MAX_ATTEMPTS", 5),
        )

    def key(self, kind: str, identifier: str) -> str:
        return f"{self.key_prefix}:{kind}:{identifier}"

    def deep_link_url(self, token: str) -> str | None:
        if self.bot_username is None:
            return None

        return f"https://t.me/{self.bot_username}?start={token}"

    @staticmethod
    def generate_secret() -> str:
        """A value suitable for the webhook secret or the hash pepper."""
        return CodeGenerator().webhook_secret()
