"""Telegram as a second authentication factor.

The whole protocol with no framework underneath it: linking (three flows),
challenge (two directions), verification, unlinking. Everything it touches
arrives through a protocol, so the same class runs on Redis and Postgres or on
dictionaries in a test.

See SPEC.md for the normative protocol this implements.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Any, Callable

from .codes import CodeGenerator, CodeHasher
from .config import Config
from .contracts import (
    ANY_GENERATION,
    Clock,
    CodeStore,
    Identity,
    IdentityStore,
    Logger,
    Messages,
    NullLogger,
    SystemClock,
    TelegramClient,
    is_verified,
)
from .errors import ChatAlreadyLinked, ErrorCode
from .results import ChallengeResult, LinkRequest, LinkResult, VerificationResult

#: The default purpose, for an ordinary sign-in.
PURPOSE_LOGIN = "login"

#: The purpose of a code the user fetched themselves with /code.
#:
#: Such a code carries no knowledge of what it is about to authorise, so it
#: satisfies any requested purpose. That is sound because the user asked for it
#: deliberately - nothing the application did caused it to exist.
PURPOSE_ON_DEMAND = "on_demand"

#: Proving the current factor before rebinding to a new chat.
PURPOSE_REPLACE = "replace"

#: Proving the current factor before removing it.
PURPOSE_UNLINK = "unlink"


class TelegramTwoFactor:
    def __init__(
        self,
        config: Config,
        store: CodeStore,
        identities: IdentityStore,
        telegram: TelegramClient,
        messages: Messages,
        clock: Clock | None = None,
        logger: Logger | None = None,
        codes: CodeGenerator | None = None,
        hasher: CodeHasher | None = None,
    ) -> None:
        self.config = config
        self._store = store
        self._identities = identities
        self._telegram = telegram
        self._messages = messages
        self._clock = clock or SystemClock()
        self._logger = logger or NullLogger()
        self._codes = codes or CodeGenerator()
        self._hasher = hasher or CodeHasher(config.hash_algorithm, config.hash_pepper)

    # ----------------------------------------------------------- identity

    def is_linked(self, user_id: str) -> bool:
        """Whether this account has a proven Telegram second factor."""
        return is_verified(self._identities.find_by_user_id(user_id))

    def identity(self, user_id: str) -> Identity | None:
        return self._identities.find_by_user_id(user_id)

    def identity_for_chat(self, chat_id: str) -> Identity | None:
        """The enrollment behind a chat, for the webhook side of the protocol."""
        return self._identities.find_by_chat_id(chat_id)

    # ------------------------------------------------------------ linking

    def start_deep_link(self, user_id: str) -> LinkRequest:
        """Begin the deeplink flow: mint a nonce bound to this account.

        Hand the returned url to the user as a button, or as a QR code when
        they are on a desktop with Telegram on their phone. The token is bound
        to the account before it ever reaches Telegram, which is what makes
        this flow preferable to the paste flow: there is no window in which a
        token is valid for whoever happens to present it.

        Minting is harmless for an already-linked account, so this does not
        check; the check happens in ``complete_deep_link``.
        """
        token = self._codes.deep_link_token()
        expires_at = self._clock.now() + self.config.link_ttl

        self._store.put(
            self.config.key("link", self._hasher.hash(token)),
            {"user_id": user_id, "expires_at": expires_at},
            self.config.link_ttl,
        )

        self._logger.info("telegram-2fa: deeplink issued", {"user_id": user_id})

        return LinkRequest(token, expires_at, self.config.deep_link_url(token))

    def complete_deep_link(self, token: str, chat_id: str) -> LinkResult:
        """Finish the deeplink flow, from the /start payload in a webhook update."""
        # Single use, and taken atomically: a token read now and deleted later
        # can be resolved twice by two concurrent /start messages, and a token
        # that survives a failed attempt can be retried by anyone who saw it -
        # and it travelled through a chat, so others may have.
        record = self._store.take(self.config.key("link", self._hasher.hash(token)))

        if not isinstance(record, dict) or not record.get("user_id"):
            self._logger.warning(
                "telegram-2fa: deeplink token not resolvable", {"chat_id": chat_id}
            )

            return LinkResult.failed(ErrorCode.INVALID_TOKEN)

        if int(record.get("expires_at", 0)) < self._clock.now():
            return LinkResult.failed(ErrorCode.INVALID_TOKEN)

        replace = record.get("replace") is True
        proven = record.get("generation")
        proven = proven if isinstance(proven, str) else None
        user_id = str(record["user_id"])

        # A replacement token carries authority over an existing enrollment, so
        # it is only valid against the one whose possession was proved. If that
        # enrollment has since changed - recovered through support, unlinked,
        # or already replaced - the proof no longer refers to anything.
        if replace and not self._generation_is_current(user_id, proven):
            self._logger.warning(
                "telegram-2fa: stale replacement token rejected", {"user_id": user_id}
            )

            return LinkResult.failed(ErrorCode.INVALID_TOKEN)

        return self._bind(user_id, chat_id, replace=replace, proven_generation=proven)

    def start_paste_link(self, chat_id: str) -> LinkRequest:
        """Begin the paste flow, from the bot side: mint a code bound to this chat."""
        code = self._codes.link_code(self.config.link_code_length)
        expires_at = self._clock.now() + self.config.link_ttl

        self._store.put(
            self.config.key("link", self._hasher.hash(code)),
            {"chat_id": chat_id, "expires_at": expires_at},
            self.config.link_ttl,
        )

        self._logger.info("telegram-2fa: paste link code issued")

        return LinkRequest(code, expires_at, None)

    def complete_paste_link(self, user_id: str, code: str) -> LinkResult:
        """Finish the paste flow, from an authenticated page in your application.

        Two things this cannot check are the caller's: that ``user_id`` comes
        from the session rather than the request body, and that the endpoint is
        rate-limited. Without the rate limit the attempt budget on this flow is
        unbounded, and link codes share one namespace across all users.
        """
        normalised = code.strip().upper()
        record = self._store.take(self.config.key("link", self._hasher.hash(normalised)))

        if not isinstance(record, dict) or not record.get("chat_id"):
            self._logger.warning(
                "telegram-2fa: paste code not resolvable", {"user_id": user_id}
            )

            return LinkResult.failed(ErrorCode.INVALID_TOKEN)

        if int(record.get("expires_at", 0)) < self._clock.now():
            return LinkResult.failed(ErrorCode.INVALID_TOKEN)

        return self._bind(user_id, str(record["chat_id"]))

    def start_chat_replacement(
        self, user_id: str, code: str
    ) -> LinkRequest | VerificationResult:
        """Begin moving the factor to a different Telegram account.

        Linking never silently moves a verified enrollment, because a flow that
        did would let anyone holding a session attach their own chat. So
        replacement is explicit and costs a code from the chat being replaced.

        A user who has lost the old chat entirely cannot do this, and belongs
        in ``unlink_after_external_proof`` instead.
        """
        identity = self._identities.find_by_user_id(user_id)

        if not is_verified(identity):
            return VerificationResult.failed(ErrorCode.NOT_LINKED)

        assert identity is not None

        # Captured *before* verifying, because this is the enrollment the user
        # is about to prove possession of. It is what the token must record.
        proven = identity.generation

        proof = self.verify(user_id, code, PURPOSE_REPLACE)

        if not proof.ok:
            return proof

        if proven is None:
            # A row enrolled before the generation existed. Assign one,
            # conditional on it still being absent - which doubles as the check
            # below: if anything changed the enrollment while the code was
            # being verified, the generation is no longer None and this
            # transition declines.
            assigned = self._identities.transition(
                user_id, identity.chat_id, None, self._codes.enrollment_generation()
            )

            if assigned is None or not assigned.is_verified() or assigned.generation is None:
                return VerificationResult.failed(ErrorCode.EXPIRED)

            return self._mint_replacement_token(user_id, assigned.generation)

        # Confirm the enrollment did not move while the code was being
        # verified, and reject if it did. What must never happen is adopting
        # the generation read *after* verification: a recovery landing in that
        # window would have its own new generation, and recording that would
        # hand this token authority over an enrollment the user never proved.
        after = self._identities.find_by_user_id(user_id)

        if (
            not is_verified(after)
            or after is None
            or after.generation is None
            or not hmac.compare_digest(after.generation, proven)
        ):
            self._logger.warning(
                "telegram-2fa: enrollment changed during replacement authorisation",
                {"user_id": user_id},
            )

            return VerificationResult.failed(ErrorCode.EXPIRED)

        return self._mint_replacement_token(user_id, proven)

    def _mint_replacement_token(self, user_id: str, proven_generation: str) -> LinkRequest:
        """Store a replacement token against exactly one enrollment generation.

        Separate so there is a single place the generation is written, and so
        no caller can pass one it read later than the proof.
        """
        token = self._codes.deep_link_token()
        expires_at = self._clock.now() + self.config.link_ttl

        # The replace mark lives on the stored token, not on the call that
        # resolves it. Taking it from the resolution side would make the proof
        # skippable by presenting an ordinary token.
        self._store.put(
            self.config.key("link", self._hasher.hash(token)),
            {
                "user_id": user_id,
                "expires_at": expires_at,
                "replace": True,
                "generation": proven_generation,
            },
            self.config.link_ttl,
        )

        self._logger.info(
            "telegram-2fa: chat replacement authorised", {"user_id": user_id}
        )

        return LinkRequest(token, expires_at, self.config.deep_link_url(token))

    def _bind(
        self,
        user_id: str,
        chat_id: str,
        replace: bool = False,
        proven_generation: str | None = None,
    ) -> LinkResult:
        """Record the enrollment, as one conditional transition.

        Everything here hangs on handing the store an expectation rather than
        reading state and then writing it. The validation above happens a
        moment earlier, and a recovery or a competing link can land in between;
        passing the generation we believed was current means such a write fails
        instead of overwriting whatever replaced it.
        """
        existing = self._identities.find_by_user_id(user_id)
        replacing: Identity | None = None

        if is_verified(existing):
            assert existing is not None

            # Re-presenting the same chat is a double submit, not a conflict.
            if existing.chat_id == chat_id:
                return LinkResult.linked(existing)

            if not replace:
                return LinkResult.failed(ErrorCode.ALREADY_LINKED)

            replacing = existing

        expected = proven_generation if replace else (existing.generation if existing else None)
        holder = self._identities.find_by_chat_id(chat_id)

        if holder is not None and holder.user_id != user_id:
            self._logger.warning(
                "telegram-2fa: chat already linked to another account",
                {"user_id": user_id},
            )

            return LinkResult.failed(ErrorCode.ALREADY_LINKED)

        try:
            # One write. It either moves the enrollment or changes nothing, so
            # a replacement onto an unavailable chat - or one overtaken by a
            # recovery - leaves the existing enrollment exactly as it was,
            # rather than stripping the account of its second factor as a side
            # effect of a request that failed.
            identity = self._identities.transition(
                user_id, chat_id, expected, self._codes.enrollment_generation()
            )
        except ChatAlreadyLinked:
            # The store's uniqueness constraint caught what the check above
            # raced past. The loser's existing enrollment is untouched.
            return LinkResult.failed(ErrorCode.ALREADY_LINKED)

        if identity is None:
            self._logger.warning(
                "telegram-2fa: enrollment changed during link",
                {"user_id": user_id, "replace": replace},
            )

            return LinkResult.failed(
                ErrorCode.INVALID_TOKEN if replace else ErrorCode.ALREADY_LINKED
            )

        if replacing is not None:
            # Any code in flight was delivered to the chat that is no longer
            # the factor. The generation has already changed, so such a code is
            # unusable even if this cleanup loses a race; this stops it
            # lingering.
            self._clear_pending(user_id)

            # Afterwards, so a failed replacement never announces one.
            if replacing.chat_id is not None:
                self._telegram.send_message(
                    replacing.chat_id, self._messages.unlinked(self.config.app_name)
                )

            self._logger.info("telegram-2fa: factor replaced", {"user_id": user_id})

            return LinkResult.linked(identity)

        self._logger.info("telegram-2fa: linked", {"user_id": user_id})

        return LinkResult.linked(identity)

    # ---------------------------------------------------------- challenge

    def push(self, user_id: str, purpose: str = PURPOSE_LOGIN) -> ChallengeResult:
        """Issue a code and send it to the linked chat.

        The code is not in the return value. It is generated, hashed into the
        store, handed to Telegram, and dropped.
        """
        identity = self._identities.find_by_user_id(user_id)

        if not is_verified(identity):
            return ChallengeResult.failed(ErrorCode.NOT_LINKED)

        assert identity is not None

        blocked = self._reserve_send(user_id)

        if blocked is not None:
            return ChallengeResult.failed(ErrorCode.COOLDOWN, blocked)

        code, challenge_id = self._issue(user_id, purpose, identity.generation)

        sent = self._telegram.send_message(
            str(identity.chat_id), self._messages.code(code, self.config.code_ttl)
        )

        if not sent:
            # Drop the code rather than leaving one live that the user never
            # received. Conditionally, so a slow failure cannot delete a code
            # issued after it.
            self._discard_challenge(user_id, challenge_id)
            self._logger.error("telegram-2fa: delivery failed", {"user_id": user_id})

            return ChallengeResult.failed(ErrorCode.SEND_FAILED)

        self._logger.info(
            "telegram-2fa: code sent", {"user_id": user_id, "purpose": purpose}
        )

        return ChallengeResult.sent(
            self._clock.now() + self.config.code_ttl,
            self._clock.now() + self.config.cooldown,
        )

    def pull(self, chat_id: str, purpose: str = PURPOSE_ON_DEMAND) -> ChallengeResult:
        """The user asked the bot for a code.

        Writes the same store key as ``push``, so one verification call accepts
        a code from either direction - see the single-key rule in SPEC.md 4.
        """
        identity = self._identities.find_by_chat_id(chat_id)

        if not is_verified(identity):
            return ChallengeResult.failed(ErrorCode.NOT_LINKED)

        assert identity is not None

        blocked = self._reserve_send(identity.user_id)

        if blocked is not None:
            return ChallengeResult.failed(ErrorCode.COOLDOWN, blocked)

        code, challenge_id = self._issue(identity.user_id, purpose, identity.generation)

        sent = self._telegram.send_message(
            chat_id, self._messages.code(code, self.config.code_ttl)
        )

        if not sent:
            self._discard_challenge(identity.user_id, challenge_id)

            return ChallengeResult.failed(ErrorCode.SEND_FAILED)

        self._logger.info(
            "telegram-2fa: code issued on demand", {"user_id": identity.user_id}
        )

        return ChallengeResult.sent(
            self._clock.now() + self.config.code_ttl,
            self._clock.now() + self.config.cooldown,
        )

    def _issue(
        self, user_id: str, purpose: str, generation: str | None
    ) -> tuple[str, str]:
        code = self._codes.two_factor_code(self.config.code_length)
        challenge_id = secrets.token_hex(8)

        self._store.put(
            self.config.key("code", user_id),
            {
                # Bound to the account, so a digest lifted from the store
                # cannot be matched against another user's code.
                "hash": self._hasher.hash(code, user_id),
                "expires_at": self._clock.now() + self.config.code_ttl,
                "attempts": 0,
                "purpose": purpose,
                "generation": generation,
                "challenge_id": challenge_id,
            },
            self.config.code_ttl,
        )

        return code, challenge_id

    def _discard_challenge(self, user_id: str, challenge_id: str) -> None:
        """Drop a challenge only if it is still the one we issued.

        A delivery failure must not delete a newer challenge. That is
        reachable: if sending blocks past the cooldown, the user can be issued
        a fresh code before this handler runs, and an unconditional delete
        would throw away a code the user is holding.
        """
        key = self.config.key("code", user_id)
        record = self._store.take(key)

        if not isinstance(record, dict):
            return

        if record.get("challenge_id") != challenge_id:
            # Someone else's challenge. Put it back as we found it.
            self._store.put(
                key,
                record,
                max(1, int(record.get("expires_at", 0)) - self._clock.now()),
            )

            return

        self._store.forget(self.config.key("cooldown", user_id))

    def _reserve_send(self, user_id: str) -> int | None:
        """Reserve the right to send, atomically.

        Checking for a cooldown and then writing one is two operations, and two
        challenges arriving together both see no cooldown and both send.
        ``add`` makes the write itself the check.
        """
        key = self.config.key("cooldown", user_id)
        next_send_at = self._clock.now() + self.config.cooldown

        if self._store.add(key, next_send_at, self.config.cooldown):
            return None

        held = self._store.get(key)

        # Coerced, not compared: a store may hand back a numeric string.
        try:
            return int(held)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return next_send_at

    def _clear_pending(self, user_id: str) -> None:
        self._store.forget(self.config.key("code", user_id))
        self._store.forget(self.config.key("cooldown", user_id))

    # ------------------------------------------------------- verification

    def verify(
        self, user_id: str, code: str, purpose: str = PURPOSE_LOGIN
    ) -> VerificationResult:
        """Check a submitted code.

        Single use on success, attempt-budgeted on failure, constant-time
        throughout. ``purpose`` must match what the code was issued for and
        defaults to login exactly as ``push`` does; there is deliberately no
        way to skip the check, because a default of "compare against nothing"
        means the binding does nothing unless every call site opts in, and the
        call site that forgets is the one that matters.
        """
        key = self.config.key("code", user_id)

        # Take the record, rather than read it and delete it later. Those are
        # two operations with a gap between them, and two verifications
        # arriving together both read the live record, both match, and both
        # succeed - a single-use code used twice, with the attempt counter
        # losing increments to the same race.
        record = self._store.take(key)

        if not isinstance(record, dict) or not isinstance(record.get("hash"), str):
            return VerificationResult.failed(ErrorCode.EXPIRED)

        attempts = int(record.get("attempts", 0))

        # The record is already gone in each of these branches, which is what
        # we want: a spent or expired code should not come back.
        if attempts >= self.config.max_attempts:
            return VerificationResult.failed(ErrorCode.TOO_MANY_ATTEMPTS, 0)

        if int(record.get("expires_at", 0)) < self._clock.now():
            return VerificationResult.failed(ErrorCode.EXPIRED)

        # The enrollment this challenge belongs to must still be current.
        # Anything that changed it revoked this challenge, and the record is
        # already gone because we took it. This check, not the cleanup in
        # _bind, is what makes revocation sound: cleanup races a concurrent
        # verification, while this cannot.
        if not self._generation_matches(user_id, record.get("generation")):
            self._logger.warning(
                "telegram-2fa: challenge from a superseded enrollment",
                {"user_id": user_id},
            )

            return VerificationResult.failed(ErrorCode.EXPIRED)

        if not self._purpose_satisfied(str(record.get("purpose", "")), purpose):
            # A code minted to confirm a login should not also confirm a
            # withdrawal. Count it as an attempt rather than a free retry, and
            # report `invalid`: telling the caller a live code exists for some
            # other purpose is information it has not proved it should have.
            return self._record_failed_attempt(key, record, attempts, user_id)

        if not self._hasher.matches(str(record["hash"]), code.strip(), user_id):
            return self._record_failed_attempt(key, record, attempts, user_id)

        self._logger.info(
            "telegram-2fa: verified",
            {"user_id": user_id, "purpose": record.get("purpose")},
        )

        return VerificationResult.passed()

    def _purpose_satisfied(self, stored: str, requested: str) -> bool:
        """Whether a stored code may be used for the purpose being requested.

        An on-demand code is general-purpose by default, because it cannot know
        what it is for and the user asked for it deliberately. That is a policy
        rather than a law, so ``on_demand_satisfies`` can narrow it.
        """
        if stored == requested:
            return True

        if stored != PURPOSE_ON_DEMAND:
            return False

        return (
            self.config.on_demand_satisfies is None
            or requested in self.config.on_demand_satisfies
        )

    def _generation_matches(self, user_id: str, generation: Any) -> bool:
        """Whether a challenge belongs to the account's current enrollment.

        A challenge issued before the generation existed (a row migrated from
        an older version) is accepted only while the account has no generation
        at all, so upgrading does not invalidate codes in flight.
        """
        identity = self._identities.find_by_user_id(user_id)
        current = identity.generation if identity else None

        if current is None:
            return generation is None

        return isinstance(generation, str) and hmac.compare_digest(current, generation)

    def _generation_is_current(self, user_id: str, generation: Any) -> bool:
        if not isinstance(generation, str) or generation == "":
            return False

        identity = self._identities.find_by_user_id(user_id)

        if not is_verified(identity) or identity is None or identity.generation is None:
            return False

        return hmac.compare_digest(identity.generation, generation)

    def _record_failed_attempt(
        self, key: str, record: dict[str, Any], attempts: int, user_id: str
    ) -> VerificationResult:
        spent = attempts + 1
        remaining = self.config.max_attempts - spent

        if remaining <= 0:
            return VerificationResult.failed(ErrorCode.TOO_MANY_ATTEMPTS, 0)

        # Re-store under the code's own remaining lifetime. A fresh full TTL
        # would let an attacker keep a code alive indefinitely by guessing
        # wrong, removing the time limit altogether.
        #
        # A revocation can land between the take above and this write, so this
        # re-check keeps a dead challenge from being written back. It is
        # best-effort by nature, and does not need to be airtight, because
        # verify() re-checks the generation before accepting anything. A
        # resurrected record is inert.
        if self._generation_matches(user_id, record.get("generation")):
            self._store.put(
                key,
                {**record, "attempts": spent},
                max(1, int(record.get("expires_at", 0)) - self._clock.now()),
            )

        return VerificationResult.failed(ErrorCode.INVALID, remaining)

    # --------------------------------------------------------- unlinking

    def unlink(self, user_id: str, code: str) -> VerificationResult:
        """Remove the factor, proving possession of it first.

        Unlinking is the step an attacker with a stolen session but no phone
        needs, so it demands the same proof as any other protected action.
        """
        identity = self._identities.find_by_user_id(user_id)

        if not is_verified(identity):
            return VerificationResult.failed(ErrorCode.NOT_LINKED)

        assert identity is not None

        # Under PURPOSE_UNLINK, so a code pushed for a login cannot remove the
        # factor. A code the user fetched with /code still works, because
        # on-demand codes are general-purpose.
        result = self.verify(user_id, code, PURPOSE_UNLINK)

        if not result.ok:
            return result

        if not self._detach(identity, identity.generation):
            # The enrollment moved while we were verifying, so the code we just
            # accepted no longer refers to what is stored.
            return VerificationResult.failed(ErrorCode.EXPIRED)

        return VerificationResult.passed()

    def unlink_after_external_proof(self, user_id: str, reason: str) -> bool:
        """Remove the factor when another factor has already proved the request.

        For recovery paths: the user still has their authenticator, or passed
        an out-of-band check, but has lost the Telegram account. The caller
        takes responsibility for that proof - this method performs none.
        """
        identity = self._identities.find_by_user_id(user_id)

        if identity is None:
            return False

        # Unconditional: the caller has proved identity by other means, and a
        # recovery must not be blocked by whatever the account's state is.
        self._detach(identity, ANY_GENERATION)

        self._logger.warning(
            "telegram-2fa: unlinked via external proof",
            {"user_id": user_id, "reason": reason},
        )

        return True

    def _detach(self, identity: Identity, expected: str | None) -> bool:
        """Remove the enrollment and revoke everything that referred to it.

        The generation is advanced even though no chat remains, which is the
        whole reason it is stored separately from the chat id: a replacement
        token or a challenge minted before this point stays void afterwards,
        and would otherwise come back to life the moment the user links again.
        """
        moved = self._identities.transition(
            identity.user_id, None, expected, self._codes.enrollment_generation()
        )

        if moved is None:
            self._logger.warning(
                "telegram-2fa: enrollment changed during unlink",
                {"user_id": identity.user_id},
            )

            return False

        self._clear_pending(identity.user_id)

        # Best effort: the user should hear that their factor was removed even
        # if, especially if, they did not do it themselves.
        if identity.chat_id is not None:
            self._telegram.send_message(
                identity.chat_id, self._messages.unlinked(self.config.app_name)
            )

        self._logger.info("telegram-2fa: unlinked", {"user_id": identity.user_id})

        return True
