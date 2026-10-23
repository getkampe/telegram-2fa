"""A production code store on Redis.

Values are JSON, in the key layout and field names of SPEC.md section 9, so the
PHP and Node implementations read and write the same records.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from ..errors import ConfigurationError

_TAKE_SCRIPT = """local v = redis.call('GET', KEYS[1])
if v then redis.call('DEL', KEYS[1]) end
return v"""


class RedisLike(Protocol):
    """The part of a Redis client this store uses.

    Declared structurally so the package keeps zero runtime dependencies, and
    satisfied by redis-py. ``getdel`` requires Redis 6.2; ``eval`` covers
    older servers.
    """

    def get(self, name: str) -> Any: ...

    def delete(self, *names: str) -> Any: ...

    def set(self, name: str, value: Any, ex: int | None = ..., nx: bool = ...) -> Any: ...


class RedisCodeStore:
    """TTLs are set by Redis itself, which is why each record also carries its
    own ``expires_at``: the two must agree, and the explicit check is what keeps
    expiry correct on a replica whose clock has drifted.
    """

    def __init__(self, redis: Any) -> None:
        self._redis = redis

        # Resolved once, at construction, so a deployment missing an atomic
        # get-and-delete fails here rather than silently verifying one code
        # twice under load.
        if hasattr(redis, "getdel"):
            self._take_impl = lambda key: redis.getdel(key)
        elif hasattr(redis, "eval"):
            self._take_impl = lambda key: redis.eval(_TAKE_SCRIPT, 1, key)
        else:
            raise ConfigurationError(
                "This Redis client exposes neither GETDEL (getdel) nor EVAL, so it "
                "cannot remove a key and return its value in one operation. Without "
                "that, two simultaneous verifications of the same code can both "
                "succeed. Upgrade the client, or implement CodeStore against a "
                "primitive that is atomic."
            )

    def get(self, key: str) -> Any | None:
        return self._decode(self._redis.get(key))

    def put(self, key: str, value: Any, ttl_seconds: int) -> None:
        self._redis.set(key, json.dumps(value), ex=ttl_seconds)

    def forget(self, key: str) -> None:
        self._redis.delete(key)

    def take(self, key: str) -> Any | None:
        return self._decode(self._take_impl(key))

    def add(self, key: str, value: Any, ttl_seconds: int) -> bool:
        # SET NX returns None when the key already exists, which is exactly the
        # reservation semantics we need.
        return bool(self._redis.set(key, json.dumps(value), ex=ttl_seconds, nx=True))

    @staticmethod
    def _decode(raw: Any) -> Any | None:
        if raw is None:
            return None

        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")

        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            # A value that is not JSON was not written by this library.
            # Treating it as absent is safer than raising inside a
            # verification path.
            return None
