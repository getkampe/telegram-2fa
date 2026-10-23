"""kampe-telegram-2fa: Telegram as a second authentication factor.

Zero runtime dependencies. The protocol is specified in SPEC.md at the root of
the repository, and the PHP and Node packages implement the same one, so all
three interoperate against one bot and one store.

Minimal wiring::

    from kampe_telegram_2fa import (
        Config, DefaultMessages, HttpTelegramClient, MemoryCodeStore,
        TelegramTwoFactor,
    )

    config = Config.from_env()
    tfa = TelegramTwoFactor(
        config=config,
        store=RedisCodeStore(redis),
        identities=my_identity_store,
        telegram=HttpTelegramClient(config.bot_token),
        messages=DefaultMessages(),
    )

This port is synchronous; call it from asyncio with ``asyncio.to_thread``.
"""

from .codes import LINK_ALPHABET, TOKEN_ALPHABET, CodeGenerator, CodeHasher
from .config import Config
from .contracts import (
    ANY_GENERATION,
    Clock,
    CodeStore,
    FrozenClock,
    Identity,
    IdentityStore,
    Logger,
    Messages,
    NullLogger,
    StdlibLogger,
    SystemClock,
    TelegramClient,
    is_verified,
)
from .errors import (
    ChatAlreadyLinked,
    ConfigurationError,
    ErrorCode,
    TelegramRequestFailed,
    TelegramTwoFactorError,
)
from .results import ChallengeResult, LinkRequest, LinkResult, VerificationResult
from .service import (
    PURPOSE_LOGIN,
    PURPOSE_ON_DEMAND,
    PURPOSE_REPLACE,
    PURPOSE_UNLINK,
    TelegramTwoFactor,
)
from .stores.memory import MemoryCodeStore, MemoryIdentityStore
from .stores.redis import RedisCodeStore, RedisLike
from .telegram.client import HttpTelegramClient
from .telegram.messages import DefaultMessages, escape_html
from .webhook.handler import UpdateHandler
from .webhook.verifier import SECRET_HEADER, TELEGRAM_RANGES, WebhookVerifier

__version__ = "1.0.0"

__all__ = [
    "ANY_GENERATION",
    "ChallengeResult",
    "ChatAlreadyLinked",
    "Clock",
    "CodeGenerator",
    "CodeHasher",
    "CodeStore",
    "Config",
    "ConfigurationError",
    "DefaultMessages",
    "ErrorCode",
    "FrozenClock",
    "HttpTelegramClient",
    "Identity",
    "IdentityStore",
    "LINK_ALPHABET",
    "LinkRequest",
    "LinkResult",
    "Logger",
    "MemoryCodeStore",
    "MemoryIdentityStore",
    "Messages",
    "NullLogger",
    "PURPOSE_LOGIN",
    "PURPOSE_ON_DEMAND",
    "PURPOSE_REPLACE",
    "PURPOSE_UNLINK",
    "RedisCodeStore",
    "RedisLike",
    "SECRET_HEADER",
    "StdlibLogger",
    "SystemClock",
    "TELEGRAM_RANGES",
    "TelegramClient",
    "TelegramRequestFailed",
    "TelegramTwoFactor",
    "TelegramTwoFactorError",
    "TOKEN_ALPHABET",
    "UpdateHandler",
    "VerificationResult",
    "WebhookVerifier",
    "escape_html",
    "is_verified",
]
