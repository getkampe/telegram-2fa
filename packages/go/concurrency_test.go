package telegram2fa_test

import (
	"testing"
	"time"

	telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
	"github.com/getkampe/telegram-2fa/packages/go/store"
)

// SPEC.md 5.1 — the state transitions that must be atomic.
//
// These run real goroutines against the shipped stores, released together by a
// WaitGroup barrier, and CI runs the whole package under -race. That is the
// strongest check of the four ports: PHP has no threads in a request, Node has
// one event loop, and Python's GIL hides short critical sections unless the
// clock is made to yield. Go goroutines are genuinely preemptible and the race
// detector reports unsynchronised access directly.

func TestOnlyOneOfManyConcurrentTakesGetsTheValue(t *testing.T) {
	codes := store.NewMemoryCodeStore(newFrozenClock())

	if err := codes.Put("k", "value", time.Minute); err != nil {
		t.Fatalf("put: %v", err)
	}

	results := race(32, func(int) any {
		value, err := codes.Take("k")
		if err != nil {
			t.Errorf("take: %v", err)
		}

		return value
	})

	got := 0

	for _, result := range results {
		if result != nil {
			got++
		}
	}

	if got != 1 {
		t.Fatalf("exactly one caller may receive the value, %d did", got)
	}
}

func TestOnlyOneOfManyConcurrentAddsReserves(t *testing.T) {
	codes := store.NewMemoryCodeStore(newFrozenClock())

	results := race(32, func(index int) bool {
		won, err := codes.Add("k", index, time.Minute)
		if err != nil {
			t.Errorf("add: %v", err)
		}

		return won
	})

	won := 0

	for _, result := range results {
		if result {
			won++
		}
	}

	if won != 1 {
		t.Fatalf("exactly one reservation may win, %d did", won)
	}
}

func TestOnlyOneOfManyConcurrentTransitionsApplies(t *testing.T) {
	identities := store.NewMemoryIdentityStore(newFrozenClock())

	results := race(16, func(index int) *telegram2fa.Identity {
		identity, err := identities.Transition(
			"u", "chat-"+formatIndex(index), "", "gen-"+formatIndex(index))
		if err != nil {
			t.Errorf("transition: %v", err)
		}

		return identity
	})

	applied := 0
	var winner *telegram2fa.Identity

	for _, result := range results {
		if result != nil {
			applied++
			winner = result
		}
	}

	if applied != 1 {
		t.Fatalf("all started from the same expectation, so one may apply, %d did", applied)
	}

	// And the stored row is the winner's, not a mixture.
	stored, err := identities.FindByUserID("u")
	if err != nil {
		t.Fatalf("findByUserID: %v", err)
	}

	if stored.ChatID != winner.ChatID || stored.Generation != winner.Generation {
		t.Fatalf("expected %#v, stored %#v", winner, stored)
	}
}

func TestOneChatCannotBeClaimedByTwoAccountsConcurrently(t *testing.T) {
	identities := store.NewMemoryIdentityStore(newFrozenClock())

	results := race(16, func(index int) bool {
		_, err := identities.Transition(
			"user-"+formatIndex(index), "shared", "", "gen-"+formatIndex(index))

		return err == nil
	})

	won := 0

	for _, result := range results {
		if result {
			won++
		}
	}

	if won != 1 {
		t.Fatalf("a chat belongs to one account, %d claims succeeded", won)
	}
}

func TestExactlyOneOfManyConcurrentVerificationsSucceeds(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", "")
	code := h.LastCode()

	results := race(32, func(int) bool {
		result, err := h.Service.Verify("user-1", code, "")
		if err != nil {
			t.Errorf("verify: %v", err)
		}

		return result.OK
	})

	succeeded := 0

	for _, result := range results {
		if result {
			succeeded++
		}
	}

	if succeeded != 1 {
		t.Fatalf("a single-use code must authorise exactly one action, %d succeeded", succeeded)
	}
}

// "Concurrent failures preserve the attempt budget" means no increment is lost
// — not that thirty-two parallel guesses spend thirty-two attempts. With an
// atomic take only the holder's guess is compared at all; the rest are told
// expired without being evaluated, and a guess that is never evaluated cannot
// be a hit.
//
// The property that must hold is that the number of guesses actually compared
// never exceeds the budget, however many goroutines are thrown at it.
func TestParallelismCannotWinMoreGuessesThanTheBudget(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", "")
	wrong := h.WrongCode(h.LastCode())

	results := race(32, func(int) telegram2fa.ErrorCode {
		result, err := h.Service.Verify("user-1", wrong, "")
		if err != nil {
			t.Errorf("verify: %v", err)
		}

		return result.Error
	})

	evaluated := 0

	for _, result := range results {
		if result == telegram2fa.ErrInvalid {
			evaluated++
		}
	}

	if evaluated < 1 {
		t.Fatal("at least one guess must actually be checked")
	}

	if evaluated > h.Config.MaxAttempts {
		t.Fatalf(
			"parallelism must not buy more comparisons than the budget allows: %d > %d",
			evaluated, h.Config.MaxAttempts)
	}
}

func TestManyConcurrentChallengesSendOneCode(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")

	results := race(16, func(int) bool {
		result, err := h.Service.Push("user-1", "")
		if err != nil {
			t.Errorf("push: %v", err)
		}

		return result.OK
	})

	sent := 0

	for _, result := range results {
		if result {
			sent++
		}
	}

	if sent != 1 {
		t.Fatalf("exactly one challenge may win the cooldown, %d did", sent)
	}

	if got := len(h.Telegram.Sent()); got != 1 {
		t.Fatalf("exactly one message may be sent, got %d", got)
	}
}

func TestOneLinkTokenBindsOneChat(t *testing.T) {
	h := newHarness(t)

	request, err := h.Service.StartDeepLink("user-1")
	if err != nil {
		t.Fatalf("startDeepLink: %v", err)
	}

	results := race(16, func(index int) bool {
		result, err := h.Service.CompleteDeepLink(request.Token, "chat-"+formatIndex(index))
		if err != nil {
			t.Errorf("completeDeepLink: %v", err)
		}

		return result.OK
	})

	bound := 0

	for _, result := range results {
		if result {
			bound++
		}
	}

	if bound != 1 {
		t.Fatalf("a link token must bind exactly one chat, %d bound", bound)
	}
}

func TestConcurrentOrdinaryLinksCannotReplaceEachOther(t *testing.T) {
	h := newHarness(t)

	tokens := make([]string, 16)

	for i := range tokens {
		request, err := h.Service.StartDeepLink("user-1")
		if err != nil {
			t.Fatalf("startDeepLink: %v", err)
		}

		tokens[i] = request.Token
	}

	results := race(16, func(index int) bool {
		result, err := h.Service.CompleteDeepLink(tokens[index], "chat-"+formatIndex(index))
		if err != nil {
			t.Errorf("completeDeepLink: %v", err)
		}

		return result.OK
	})

	linked := 0

	for _, result := range results {
		if result {
			linked++
		}
	}

	if linked != 1 {
		t.Fatalf("exactly one of many concurrent links may win, %d did", linked)
	}
}

func formatIndex(i int) string {
	digits := "0123456789"

	if i < 10 {
		return digits[i : i+1]
	}

	return digits[i/10:i/10+1] + digits[i%10:i%10+1]
}
