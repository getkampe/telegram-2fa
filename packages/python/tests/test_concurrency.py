"""SPEC.md 5.1 — the state transitions that must be atomic.

These use **real threads** against the shipped stores. That is a stronger check
than either sibling port manages: PHP has no threads in a request and Node has a
single event loop, so both have to interleave by hand. Here the interpreter can
switch between any two bytecodes, so the race is genuine rather than simulated.

A barrier makes it deterministic without sleeping: every thread blocks until all
of them have arrived, so they are released into the critical section together.
"""

from __future__ import annotations

import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from kampe_telegram_2fa import (
    ANY_GENERATION,
    PURPOSE_REPLACE,
    ErrorCode,
    FrozenClock,
    MemoryCodeStore,
    MemoryIdentityStore,
)
from kampe_telegram_2fa.errors import ChatAlreadyLinked

from .support import Harness


def race(count: int, work: Callable[[int], Any]) -> list[Any]:
    """Run ``work`` on ``count`` threads, released simultaneously.

    The barrier is what makes this deterministic: without it the first thread
    usually finishes before the last one starts, and the test would pass
    against a broken implementation most of the time.
    """
    barrier = threading.Barrier(count)

    def runner(index: int) -> Any:
        barrier.wait()

        return work(index)

    with ThreadPoolExecutor(max_workers=count) as pool:
        return [future.result() for future in [pool.submit(runner, i) for i in range(count)]]


class YieldingClock:
    """A clock that yields the GIL whenever it is read.

    Threads alone are not enough to expose a missing lock in CPython: the
    interpreter switches threads every few milliseconds by default, and a
    critical section this short normally completes inside one slice, so an
    unlocked implementation passes a threaded test most of the time. That is
    exactly the false confidence a race test must not give.

    The store reads the clock between looking a record up and removing it, so
    sleeping here forces the interleaving to happen. With the lock held the
    sleep is harmless - other threads simply wait for it - and without the lock
    a second thread reads the record the first is about to delete.
    """

    def __init__(self, now: int = 1_700_000_000, pause: float = 0.005) -> None:
        self._now = now
        self._pause = pause

    def now(self) -> int:
        time.sleep(self._pause)

        return self._now

    def advance(self, seconds: int) -> "YieldingClock":
        self._now += seconds

        return self


class MemoryCodeStoreConcurrencyTest(unittest.TestCase):
    def test_a_missing_lock_would_be_caught(self) -> None:
        """The sensitivity check for everything else in this class.

        Without the yield this suite passes against an unlocked store, so this
        is the case that makes the others mean something.
        """
        store = MemoryCodeStore(YieldingClock())
        store.put("k", "value", 60)

        results = race(8, lambda _: store.take("k"))

        self.assertEqual(
            1,
            len([r for r in results if r is not None]),
            "exactly one caller may receive the value, even when the critical "
            "section is forced to yield",
        )

    def test_add_is_atomic_when_forced_to_yield(self) -> None:
        store = MemoryCodeStore(YieldingClock())

        results = race(8, lambda i: store.add("k", i, 60))

        self.assertEqual(1, sum(1 for r in results if r))

    def test_only_one_of_many_concurrent_takes_gets_the_value(self) -> None:
        store = MemoryCodeStore(FrozenClock())
        store.put("k", "value", 60)

        results = race(16, lambda _: store.take("k"))

        self.assertEqual(
            ["value"],
            [r for r in results if r is not None],
            "exactly one caller may receive the value",
        )

    def test_only_one_of_many_concurrent_adds_reserves(self) -> None:
        store = MemoryCodeStore(FrozenClock())

        results = race(16, lambda i: store.add("k", i, 60))

        self.assertEqual(1, sum(1 for r in results if r), "exactly one reservation wins")

    def test_a_reservation_loser_does_not_overwrite_the_winner(self) -> None:
        store = MemoryCodeStore(FrozenClock())
        store.add("k", "first", 60)

        race(8, lambda i: store.add("k", f"other-{i}", 60))

        self.assertEqual("first", store.get("k"))


class MemoryIdentityStoreConcurrencyTest(unittest.TestCase):
    def test_only_one_of_many_concurrent_transitions_applies(self) -> None:
        store = MemoryIdentityStore(FrozenClock())

        results = race(
            8, lambda i: store.transition("u", f"chat-{i}", None, f"gen-{i}")
        )
        applied = [r for r in results if r is not None]

        self.assertEqual(
            1, len(applied), "all started from the same expectation, so one may apply"
        )

        # And the stored row is the winner's, not a mixture.
        stored = store.find_by_user_id("u")
        self.assertEqual(applied[0].chat_id, stored.chat_id)
        self.assertEqual(applied[0].generation, stored.generation)

    def test_one_chat_cannot_be_claimed_by_two_accounts_concurrently(self) -> None:
        store = MemoryIdentityStore(FrozenClock())

        def claim(index: int) -> str:
            try:
                store.transition(f"user-{index}", "shared-chat", None, f"gen-{index}")

                return "won"
            except ChatAlreadyLinked:
                return "refused"

        results = race(8, claim)

        self.assertEqual(1, results.count("won"), "a chat belongs to one account")
        self.assertEqual(7, results.count("refused"))


class ServiceConcurrencyTest(Harness):
    """The properties an application actually depends on."""

    def test_exactly_one_of_many_concurrent_verifications_succeeds(self) -> None:
        self.seed()
        self.tfa.push("user-1")
        code = self.last_code()

        results = race(16, lambda _: self.tfa.verify("user-1", code))

        self.assertEqual(
            1,
            sum(1 for r in results if r.ok),
            "a single-use code must authorise exactly one action",
        )

    def test_parallelism_cannot_win_more_guesses_than_the_budget(self) -> None:
        """"Concurrent failures preserve the attempt budget" means no increment
        is lost - not that sixteen parallel guesses spend sixteen attempts.

        With an atomic take only one caller holds the record at a time, so a
        guess is compared only by the holder; the rest are told expired without
        being evaluated, and a guess that is never evaluated cannot be a hit.

        The property that must hold is that the number of guesses actually
        *compared* against the code never exceeds the budget, however many
        threads are thrown at it. Real threads make this worth asserting: they
        interleave across each take-then-restore cycle, so the budget really
        does get spent here, where a single-threaded runtime would evaluate one
        guess and stop.
        """
        self.seed()
        self.tfa.push("user-1")
        wrong = self.wrong_code(self.last_code())

        results = race(16, lambda _: self.tfa.verify("user-1", wrong))

        evaluated = sum(1 for r in results if r.error == ErrorCode.INVALID)
        exhausted = sum(1 for r in results if r.error == ErrorCode.TOO_MANY_ATTEMPTS)

        self.assertGreaterEqual(evaluated, 1, "at least one guess must be checked")
        self.assertLessEqual(
            evaluated,
            self.config.max_attempts,
            "parallelism must not buy more comparisons than the budget allows",
        )

        record = self.store.get(self.config.key("code", "user-1"))

        if record is None:
            # The budget was spent, so the code is destroyed — which is only
            # correct if the evaluations actually reached the limit.
            self.assertEqual(
                self.config.max_attempts,
                evaluated + exhausted if exhausted else evaluated,
                "a code may only be destroyed once the budget is genuinely spent",
            )
        else:
            self.assertEqual(
                evaluated,
                record["attempts"],
                "every evaluated guess must be counted - a lost increment is how "
                "the budget gets beaten",
            )

    def test_the_budget_still_ends_the_code_in_sequence(self) -> None:
        self.seed()
        self.tfa.push("user-1")
        code = self.last_code()
        wrong = self.wrong_code(code)

        for _ in range(self.config.max_attempts):
            self.tfa.verify("user-1", wrong)

        self.assertFalse(
            self.tfa.verify("user-1", code).ok, "five wrong guesses must kill the code"
        )

    def test_many_concurrent_challenges_send_one_code(self) -> None:
        self.seed()

        results = race(8, lambda _: self.tfa.push("user-1"))

        self.assertEqual(1, sum(1 for r in results if r.ok))
        self.assertEqual(1, len(self.telegram.sent))

    def test_one_link_token_binds_one_chat(self) -> None:
        request = self.tfa.start_deep_link("user-1")

        results = race(
            8, lambda i: self.tfa.complete_deep_link(request.token, f"chat-{i}")
        )

        self.assertEqual(1, sum(1 for r in results if r.ok))

    def test_concurrent_ordinary_links_cannot_replace_each_other(self) -> None:
        tokens = [self.tfa.start_deep_link("user-1").token for _ in range(8)]

        results = race(8, lambda i: self.tfa.complete_deep_link(tokens[i], f"chat-{i}"))

        self.assertEqual(1, sum(1 for r in results if r.ok))

        identity = self.tfa.identity("user-1")
        self.assertIsNotNone(identity)
        # The winner's chat, not a mixture of two.
        self.assertEqual(identity.user_id, self.tfa.identity_for_chat(identity.chat_id).user_id)

    def test_concurrent_replacement_and_recovery_cannot_both_apply(self) -> None:
        self.seed()
        self.tfa.push("user-1", PURPOSE_REPLACE)
        request = self.tfa.start_chat_replacement("user-1", self.last_code())

        def work(index: int) -> str:
            if index == 0:
                result = self.tfa.complete_deep_link(request.token, "777000222")

                return "replaced" if result.ok else "replacement-refused"

            self.identities.transition(
                "user-1", None, ANY_GENERATION, "gen-recovered"
            )

            return "recovered"

        race(2, work)

        identity = self.tfa.identity("user-1")

        # Whichever order they land in, the row must be one of the two coherent
        # outcomes — never the replacement's chat under the recovery's
        # generation, or vice versa.
        self.assertIsNotNone(identity)

        if identity.generation == "gen-recovered":
            self.assertIsNone(identity.chat_id)
        else:
            self.assertIn(identity.chat_id, ("555000111", "777000222"))


if __name__ == "__main__":
    unittest.main()
