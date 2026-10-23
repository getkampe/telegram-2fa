"""SPEC.md sections 3, 4, 5 and 6 — linking, challenge, verification, purpose."""

from __future__ import annotations

import unittest

from kampe_telegram_2fa import (
    PURPOSE_LOGIN,
    PURPOSE_REPLACE,
    PURPOSE_UNLINK,
    ErrorCode,
    Identity,
    LinkRequest,
    VerificationResult,
)
from kampe_telegram_2fa.codes import LINK_ALPHABET

from .support import Harness


class ChallengeTest(Harness):
    def test_push_sends_a_code_to_the_linked_chat(self) -> None:
        self.seed()

        result = self.tfa.push("user-1")

        self.assertTrue(result.ok)
        self.assertEqual(1, len(self.telegram.sent))
        self.assertEqual("555000111", self.telegram.sent[0]["chat_id"])
        self.assertRegex(self.last_code(), r"^\d{6}$")

    def test_push_refuses_an_unlinked_account(self) -> None:
        result = self.tfa.push("nobody")

        self.assertEqual(ErrorCode.NOT_LINKED, result.error)
        self.assertEqual(0, len(self.telegram.sent))

    def test_an_unverified_link_is_not_a_second_factor(self) -> None:
        # A chat id with no verification timestamp: a link started and never
        # finished.
        self.identities._rows["user-1"] = Identity("user-1", "999", None, "gen-x")

        self.assertEqual(ErrorCode.NOT_LINKED, self.tfa.push("user-1").error)

    def test_the_code_never_appears_in_the_result(self) -> None:
        self.seed()

        result = self.tfa.push("user-1")

        # The result routinely goes straight into an HTTP response, so assert
        # on its serialised form rather than its fields.
        self.assertNotIn(self.last_code(), str(result.to_dict()))

    def test_a_second_request_inside_the_cooldown_is_refused(self) -> None:
        self.seed()

        self.tfa.push("user-1")
        second = self.tfa.push("user-1")

        self.assertEqual(ErrorCode.COOLDOWN, second.error)
        self.assertEqual(120, second.retry_after(self.clock.now()))
        self.assertEqual(1, len(self.telegram.sent))

    def test_a_request_after_the_cooldown_is_allowed(self) -> None:
        self.seed()

        self.tfa.push("user-1")
        self.clock.advance(121)

        self.assertTrue(self.tfa.push("user-1").ok)
        self.assertEqual(2, len(self.telegram.sent))

    def test_a_failed_delivery_leaves_no_live_code_and_no_cooldown(self) -> None:
        self.seed()
        self.telegram.should_fail_sending = True

        self.assertEqual(ErrorCode.SEND_FAILED, self.tfa.push("user-1").error)

        # A code the user never received must not occupy the slot, or the
        # account is stuck until the cooldown expires with no way to try again.
        self.telegram.should_fail_sending = False
        self.assertTrue(self.tfa.push("user-1").ok)

    def test_pull_issues_a_code_for_a_known_chat(self) -> None:
        self.seed()

        self.assertTrue(self.tfa.pull("555000111").ok)
        self.assertRegex(self.last_code(), r"^\d{6}$")

    def test_pull_refuses_an_unknown_chat(self) -> None:
        self.assertEqual(ErrorCode.NOT_LINKED, self.tfa.pull("404404404").error)

    def test_a_pushed_and_a_pulled_code_verify_through_the_same_call(self) -> None:
        """The single-key rule of SPEC.md section 4.

        An implementation that writes one key on push and reads another passes
        every pull-path test and silently fails every real push.
        """
        self.seed()

        self.tfa.push("user-1")
        self.assertTrue(self.tfa.verify("user-1", self.last_code()).ok)

        self.clock.advance(121)

        self.tfa.pull("555000111")
        self.assertTrue(self.tfa.verify("user-1", self.last_code()).ok)

    def test_codes_are_stored_hashed_and_bound_to_the_account(self) -> None:
        self.seed()
        self.tfa.push("user-1")

        record = self.store.get(self.config.key("code", "user-1"))

        self.assertIsInstance(record, dict)
        self.assertNotIn("code", record)
        self.assertNotEqual(self.last_code(), record["hash"])
        self.assertEqual(64, len(record["hash"]))


class VerificationTest(Harness):
    def test_the_right_code_passes(self) -> None:
        self.seed()
        self.tfa.push("user-1")

        self.assertTrue(self.tfa.verify("user-1", self.last_code()).ok)

    def test_a_wrong_code_fails_and_spends_an_attempt(self) -> None:
        self.seed()
        self.tfa.push("user-1")

        result = self.tfa.verify("user-1", self.wrong_code(self.last_code()))

        self.assertEqual(ErrorCode.INVALID, result.error)
        self.assertEqual(4, result.attempts_remaining)

    def test_a_code_works_only_once(self) -> None:
        self.seed()
        self.tfa.push("user-1")
        code = self.last_code()

        self.assertTrue(self.tfa.verify("user-1", code).ok)

        replay = self.tfa.verify("user-1", code)

        self.assertFalse(replay.ok)
        self.assertEqual(ErrorCode.EXPIRED, replay.error)

    def test_the_attempt_budget_kills_the_code(self) -> None:
        self.seed()
        self.tfa.push("user-1")
        code = self.last_code()
        wrong = self.wrong_code(code)

        for _ in range(4):
            self.assertEqual(ErrorCode.INVALID, self.tfa.verify("user-1", wrong).error)

        self.assertEqual(
            ErrorCode.TOO_MANY_ATTEMPTS, self.tfa.verify("user-1", wrong).error
        )

        # And the real code is dead too, which is the point: the budget belongs
        # to the code, not to the attacker.
        self.assertFalse(self.tfa.verify("user-1", code).ok)

    def test_an_expired_code_fails(self) -> None:
        self.seed()
        self.tfa.push("user-1")
        code = self.last_code()

        self.clock.advance(301)

        self.assertEqual(ErrorCode.EXPIRED, self.tfa.verify("user-1", code).error)

    def test_a_wrong_guess_does_not_extend_the_codes_life(self) -> None:
        self.seed()
        self.tfa.push("user-1")
        code = self.last_code()

        self.clock.advance(200)
        self.tfa.verify("user-1", self.wrong_code(code))

        self.clock.advance(101)  # 301s since issue
        self.assertEqual(ErrorCode.EXPIRED, self.tfa.verify("user-1", code).error)

    def test_whitespace_around_a_pasted_code_is_tolerated(self) -> None:
        self.seed()
        self.tfa.push("user-1")

        self.assertTrue(self.tfa.verify("user-1", f" {self.last_code()}\n").ok)

    def test_a_user_id_is_treated_as_an_opaque_string(self) -> None:
        uuid = "9b7c2f0e-4d5a-4c21-8f3b-1a2b3c4d5e6f"
        self.identities.seed(uuid, "555000111", "gen-uuid")

        self.assertTrue(self.tfa.push(uuid).ok)
        self.assertTrue(self.tfa.verify(uuid, self.last_code()).ok)

    def test_a_digest_does_not_verify_against_another_account(self) -> None:
        self.seed("user-1", "555000111")
        self.seed("user-2", "777000222")

        self.tfa.push("user-1")
        code = self.last_code()
        record = self.store.get(self.config.key("code", "user-1"))

        # Transplant user-1's record onto user-2, as a store-level attacker
        # with a known code would.
        self.store.put(self.config.key("code", "user-2"), record, 300)

        self.assertFalse(self.tfa.verify("user-2", code).ok)
        self.assertTrue(self.tfa.verify("user-1", code).ok)


class PurposeTest(Harness):
    def test_a_pushed_code_does_not_satisfy_another_purpose(self) -> None:
        self.seed()
        self.tfa.push("user-1", PURPOSE_LOGIN)

        self.assertFalse(self.tfa.verify("user-1", self.last_code(), "withdrawal").ok)

    def test_omitting_the_purpose_means_login_not_a_wildcard(self) -> None:
        self.seed()
        self.tfa.push("user-1", "withdrawal")

        self.assertFalse(self.tfa.verify("user-1", self.last_code()).ok)

    def test_an_on_demand_code_satisfies_any_purpose(self) -> None:
        self.seed()

        self.tfa.pull("555000111")
        self.assertTrue(self.tfa.verify("user-1", self.last_code(), "withdrawal").ok)

    def test_a_purpose_mismatch_reports_invalid_and_spends_an_attempt(self) -> None:
        self.seed()
        self.tfa.push("user-1", PURPOSE_LOGIN)
        code = self.last_code()

        first = self.tfa.verify("user-1", code, "withdrawal")

        self.assertEqual(ErrorCode.INVALID, first.error)
        self.assertEqual(4, first.attempts_remaining)
        self.assertEqual(3, self.tfa.verify("user-1", code, "withdrawal").attempts_remaining)

    def test_unlinking_rejects_a_code_pushed_for_a_login(self) -> None:
        self.seed()
        self.tfa.push("user-1", PURPOSE_LOGIN)

        self.assertFalse(self.tfa.unlink("user-1", self.last_code()).ok)
        self.assertTrue(self.tfa.is_linked("user-1"))

    def test_unlinking_accepts_a_code_the_user_fetched(self) -> None:
        self.seed()
        self.tfa.pull("555000111")

        self.assertTrue(self.tfa.unlink("user-1", self.last_code()).ok)
        self.assertFalse(self.tfa.is_linked("user-1"))

    def test_the_on_demand_exemption_can_be_narrowed(self) -> None:
        tfa = self.with_config(on_demand_satisfies=["login"])
        self.seed()

        tfa.pull("555000111")
        self.assertTrue(tfa.verify("user-1", self.last_code(), "login").ok)

        self.clock.advance(121)
        tfa.pull("555000111")

        self.assertFalse(tfa.verify("user-1", self.last_code(), "withdrawal").ok)


class LinkingTest(Harness):
    def test_the_deeplink_flow_links_the_account(self) -> None:
        request = self.tfa.start_deep_link("user-1")

        self.assertEqual(
            f"https://t.me/kampe_test_bot?start={request.token}", request.url
        )

        result = self.tfa.complete_deep_link(request.token, "555000111")

        self.assertTrue(result.ok)
        self.assertTrue(self.tfa.is_linked("user-1"))

    def test_a_deeplink_token_is_single_use(self) -> None:
        request = self.tfa.start_deep_link("user-1")
        self.tfa.complete_deep_link(request.token, "555000111")

        replay = self.tfa.complete_deep_link(request.token, "999999999")

        self.assertEqual(ErrorCode.INVALID_TOKEN, replay.error)

    def test_an_expired_deeplink_token_is_refused(self) -> None:
        request = self.tfa.start_deep_link("user-1")

        self.clock.advance(601)

        self.assertEqual(
            ErrorCode.INVALID_TOKEN,
            self.tfa.complete_deep_link(request.token, "555000111").error,
        )

    def test_the_link_token_is_not_stored_in_plaintext(self) -> None:
        request = self.tfa.start_deep_link("user-1")

        self.assertIsNone(self.store.get(self.config.key("link", request.token)))
        self.assertTrue(self.tfa.complete_deep_link(request.token, "555000111").ok)

    def test_the_paste_flow_links_the_account(self) -> None:
        request = self.tfa.start_paste_link("555000111")

        self.assertTrue(self.tfa.complete_paste_link("user-1", request.token).ok)
        self.assertTrue(self.tfa.is_linked("user-1"))

    def test_a_paste_code_is_accepted_in_lower_case(self) -> None:
        request = self.tfa.start_paste_link("555000111")

        self.assertTrue(
            self.tfa.complete_paste_link("user-1", request.token.lower()).ok
        )

    def test_a_paste_code_resists_enumeration(self) -> None:
        request = self.tfa.start_paste_link("555000111")

        # The paste flow's key is derived from the code, so every outstanding
        # code shares one namespace. Six digits would be guessable.
        self.assertEqual(8, len(request.token))
        self.assertTrue(all(c in LINK_ALPHABET for c in request.token))

    def test_a_chat_cannot_become_the_factor_for_a_second_account(self) -> None:
        first = self.tfa.start_deep_link("user-1")
        self.tfa.complete_deep_link(first.token, "555000111")

        second = self.tfa.start_deep_link("user-2")
        result = self.tfa.complete_deep_link(second.token, "555000111")

        self.assertEqual(ErrorCode.ALREADY_LINKED, result.error)
        self.assertFalse(self.tfa.is_linked("user-2"))
        self.assertEqual("user-1", self.tfa.identity_for_chat("555000111").user_id)

    def test_an_account_cannot_be_moved_without_a_replacement(self) -> None:
        first = self.tfa.start_deep_link("user-1")
        self.tfa.complete_deep_link(first.token, "555000111")

        second = self.tfa.start_deep_link("user-1")
        result = self.tfa.complete_deep_link(second.token, "777000222")

        self.assertEqual(ErrorCode.ALREADY_LINKED, result.error)
        self.assertEqual("555000111", self.tfa.identity("user-1").chat_id)

    def test_relinking_the_same_chat_is_idempotent(self) -> None:
        first = self.tfa.start_deep_link("user-1")
        self.tfa.complete_deep_link(first.token, "555000111")

        second = self.tfa.start_deep_link("user-1")

        self.assertTrue(self.tfa.complete_deep_link(second.token, "555000111").ok)


class ReplacementTest(Harness):
    def test_a_proven_replacement_moves_the_factor(self) -> None:
        self.seed()
        self.tfa.push("user-1", PURPOSE_REPLACE)

        request = self.tfa.start_chat_replacement("user-1", self.last_code())
        self.assertIsInstance(request, LinkRequest)

        self.assertTrue(self.tfa.complete_deep_link(request.token, "777000222").ok)
        self.assertEqual("777000222", self.tfa.identity("user-1").chat_id)
        self.assertIsNone(self.tfa.identity_for_chat("555000111"))

    def test_an_ordinary_token_cannot_move_a_verified_binding(self) -> None:
        self.seed()

        ordinary = self.tfa.start_deep_link("user-1")
        result = self.tfa.complete_deep_link(ordinary.token, "777000222")

        self.assertEqual(ErrorCode.ALREADY_LINKED, result.error)
        self.assertEqual("555000111", self.tfa.identity("user-1").chat_id)

    def test_a_refused_replacement_leaves_the_original_factor_intact(self) -> None:
        self.seed("user-1", "555000111")
        self.seed("user-2", "777000222")

        self.tfa.push("user-1", PURPOSE_REPLACE)
        request = self.tfa.start_chat_replacement("user-1", self.last_code())
        self.assertIsInstance(request, LinkRequest)

        result = self.tfa.complete_deep_link(request.token, "777000222")

        self.assertEqual(ErrorCode.ALREADY_LINKED, result.error)
        self.assertEqual("user-2", self.tfa.identity_for_chat("777000222").user_id)
        # The part that was broken in an earlier revision of the PHP and Node
        # packages: the claimant keeps what it had.
        self.assertEqual("555000111", self.tfa.identity("user-1").chat_id)

    def test_a_replacement_token_is_void_after_recovery(self) -> None:
        self.seed()
        self.tfa.push("user-1", PURPOSE_REPLACE)

        stale = self.tfa.start_chat_replacement("user-1", self.last_code())
        self.assertIsInstance(stale, LinkRequest)

        self.tfa.unlink_after_external_proof("user-1", "verified out of band")
        fresh = self.tfa.start_deep_link("user-1")
        self.tfa.complete_deep_link(fresh.token, "888000333")

        result = self.tfa.complete_deep_link(stale.token, "999000444")

        self.assertEqual(ErrorCode.INVALID_TOKEN, result.error)
        self.assertEqual("888000333", self.tfa.identity("user-1").chat_id)

    def test_unlink_and_relink_within_one_second_invalidates_old_tokens(self) -> None:
        """What a timestamp fingerprint could not express.

        ``chat_id|linked_at`` repeats when the same chat is unlinked and
        relinked inside one second, reviving every token minted beforehand.
        """
        self.seed()
        self.tfa.push("user-1", PURPOSE_REPLACE)

        stale = self.tfa.start_chat_replacement("user-1", self.last_code())
        self.assertIsInstance(stale, LinkRequest)

        before = self.clock.now()

        self.tfa.unlink_after_external_proof("user-1", "user asked")
        fresh = self.tfa.start_deep_link("user-1")
        self.tfa.complete_deep_link(fresh.token, "555000111")

        self.assertEqual(before, self.clock.now(), "the whole sequence is one second")

        self.assertFalse(self.tfa.complete_deep_link(stale.token, "999000444").ok)
        self.assertEqual("555000111", self.tfa.identity("user-1").chat_id)

    def test_replacement_invalidates_a_code_sent_to_the_old_chat(self) -> None:
        self.seed()
        self.tfa.push("user-1", PURPOSE_REPLACE)

        request = self.tfa.start_chat_replacement("user-1", self.last_code())
        self.assertIsInstance(request, LinkRequest)

        self.clock.advance(121)
        self.tfa.push("user-1", "login")
        in_flight = self.last_code()

        self.assertTrue(self.tfa.complete_deep_link(request.token, "777000222").ok)

        self.assertFalse(self.tfa.verify("user-1", in_flight, "login").ok)

    def test_a_login_code_cannot_authorise_a_replacement(self) -> None:
        self.seed()
        self.tfa.push("user-1", PURPOSE_LOGIN)

        result = self.tfa.start_chat_replacement("user-1", self.last_code())

        self.assertIsInstance(result, VerificationResult)
        self.assertFalse(result.ok)

    def test_recovery_between_the_code_and_the_token_refuses_authorisation(self) -> None:
        """The window between the code being accepted and the token written.

        An implementation that re-reads the enrollment after verifying and
        records *that* generation hands the token authority over whatever it
        finds - which, if a recovery landed in that window, is the recovered
        enrollment the user never proved. The generation written must be the
        one captured before verification.
        """
        self.seed("victim")
        self.tfa.push("victim", PURPOSE_REPLACE)
        code = self.last_code()

        # Fire the recovery on the identity read that happens after verify().
        real_find = self.identities.find_by_user_id
        reads = {"n": 0}

        def hooked(user_id: str):
            reads["n"] += 1

            if reads["n"] == 3:
                self.tfa.unlink_after_external_proof("victim", "support recovery")
                fresh = self.tfa.start_deep_link("victim")
                self.tfa.complete_deep_link(fresh.token, "888000333")

            return real_find(user_id)

        self.identities.find_by_user_id = hooked  # type: ignore[method-assign]
        request = self.tfa.start_chat_replacement("victim", code)
        self.identities.find_by_user_id = real_find  # type: ignore[method-assign]

        # Either refused outright, or the token it produced is inert. Silently
        # acquiring authority over the recovered enrollment is neither.
        if isinstance(request, LinkRequest):
            self.assertFalse(
                self.tfa.complete_deep_link(request.token, "999000444").ok,
                "a token minted after recovery must not bind",
            )

        self.assertEqual(
            "888000333",
            self.tfa.identity("victim").chat_id,
            "the recovered enrollment must survive",
        )

    def test_a_stale_record_is_inert_even_when_written_back(self) -> None:
        """Preventing a stale record from being written back is best-effort;
        accepting one is impossible.

        A verification that has already taken the record races the revocation,
        and that race cannot be closed from either side. So put the stale
        record back by hand - exactly what a lost race would do - and require
        that it still cannot authorise anything.
        """
        self.seed()
        self.tfa.push("user-1")
        code = self.last_code()

        key = self.config.key("code", "user-1")
        record = self.store.get(key)

        self.tfa.unlink_after_external_proof("user-1", "support recovery")
        fresh = self.tfa.start_deep_link("user-1")
        self.tfa.complete_deep_link(fresh.token, "888000333")

        # Resurrect it.
        self.store.put(key, record, 300)

        self.assertFalse(
            self.tfa.verify("user-1", code).ok,
            "a record from a superseded enrollment must be inert even if restored",
        )

    def test_a_late_delivery_failure_cannot_discard_a_newer_challenge(self) -> None:
        """A delivery failure handler that runs late must not throw away a code
        the user is already holding."""
        self.seed()

        def during() -> None:
            self.clock.advance(121)
            self.tfa.push("user-1", "login")

        self.telegram.fail_next_send(during)

        failed = self.tfa.push("user-1", "login")
        self.assertEqual(ErrorCode.SEND_FAILED, failed.error)

        self.assertTrue(
            self.tfa.verify("user-1", self.last_code(), "login").ok,
            "the cleanup for a failed send must only discard its own challenge",
        )

    def test_the_generation_survives_unlinking(self) -> None:
        self.seed()

        self.tfa.unlink_after_external_proof("user-1", "user asked")

        identity = self.tfa.identity("user-1")

        # The row remains, carrying a new generation and no chat: revocation
        # has to outlive the binding it revoked.
        self.assertIsNotNone(identity)
        self.assertIsNone(identity.chat_id)
        self.assertFalse(identity.is_verified())
        self.assertNotEqual("gen-user-1", identity.generation)

    def test_unlinking_notifies_the_chat_and_clears_pending(self) -> None:
        self.seed()
        self.tfa.push("user-1", PURPOSE_UNLINK)
        code = self.last_code()
        self.telegram.reset()

        self.assertTrue(self.tfa.unlink("user-1", code).ok)

        self.assertEqual(1, len(self.telegram.sent))
        self.assertIn("unlinked", self.telegram.last_message().lower())
        self.assertIsNone(self.store.get(self.config.key("code", "user-1")))
        self.assertIsNone(self.store.get(self.config.key("cooldown", "user-1")))


if __name__ == "__main__":
    unittest.main()
