"""Generation, hashing and comparison of code material."""

from __future__ import annotations

import hashlib
import hmac
import secrets

#: Crockford base32: no I, L, O or U, so there is no 1/I or 0/O confusion when
#: someone reads a code off one screen and types it into another.
LINK_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

#: URL-safe alphabet for deeplink nonces, which are never retyped by hand.
TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"


class CodeGenerator:
    """Generates the three kinds of secret this protocol uses.

    Everything here draws from :mod:`secrets`. :mod:`random` is a Mersenne
    Twister: its output is predictable from a few hundred prior samples, which
    for a 2FA code means an attacker who has seen enough codes can produce the
    next one. It is not faster in any way that matters here.
    """

    def two_factor_code(self, length: int = 6) -> str:
        """A numeric 2FA code, zero-padded.

        Numeric is safe for this one because the store key is scoped to a
        single user (SPEC.md section 6), so guessing is bounded by the attempt
        budget rather than by the size of the alphabet.
        """
        return str(secrets.randbelow(10**length)).zfill(length)

    def link_code(self, length: int = 8) -> str:
        """A link code for the paste flow.

        Not numeric: the paste flow's store key is derived from the code
        itself, so every outstanding code shares one namespace. Eight base32
        characters is 40 bits.
        """
        return "".join(secrets.choice(LINK_ALPHABET) for _ in range(length))

    def deep_link_token(self, length: int = 32) -> str:
        """A deeplink nonce. 32 characters of a 64-symbol alphabet is 192 bits."""
        return "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(length))

    def webhook_secret(self, length: int = 48) -> str:
        """A webhook secret token, in the character set Telegram accepts."""
        return "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(length))

    def enrollment_generation(self) -> str:
        """A fresh enrollment generation: 128 bits, hex.

        Random rather than a counter: nothing needs ordering, only inequality,
        and a random value cannot be predicted from the ones before it.
        """
        return secrets.token_hex(16)


class CodeHasher:
    """Hashing and comparison of code material.

    A fast keyed hash is the right primitive and not a shortcut. These codes
    live for minutes, are single-use, and are bounded by an attempt limit; a
    password KDF would add latency to every verification and buy nothing
    against a six-digit input.

    What does the work is the key, not the hash. A six-digit code has only a
    million possible values, so an unkeyed SHA-256 of one is reversed by a
    table anyone can build in seconds - which is why the pepper is required
    rather than recommended, and why the application's own secret must not live
    in the same store as the hashes.

    The context argument binds a digest to the account it belongs to, so a
    stolen digest cannot be matched against another user's, and an attacker who
    dumps the store needs a fresh search per account rather than one table for
    all of them.
    """

    def __init__(self, algorithm: str = "sha256", pepper: str = "") -> None:
        self._algorithm = algorithm
        self._pepper = pepper.encode("utf-8")

    def hash(self, code: str, context: str = "") -> str:
        """HMAC over ``context`` + NUL + ``code``.

        The NUL separator means ("ab", "c") and ("a", "bc") cannot produce the
        same input; neither value can contain a NUL byte.
        """
        message = f"{context}\0{code}".encode("utf-8")

        return hmac.new(self._pepper, message, getattr(hashlib, self._algorithm)).hexdigest()

    def matches(self, stored_hash: str, candidate: str, context: str = "") -> bool:
        """Constant-time comparison.

        ``hmac.compare_digest``, not ``==``. On secret material a comparison
        that returns at the first differing byte is a timing oracle.
        """
        return hmac.compare_digest(stored_hash, self.hash(candidate, context))
