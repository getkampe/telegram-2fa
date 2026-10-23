package telegram2fa_test

import (
	"testing"

	telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
)

// SPEC.md 3.3 — moving the factor to a different Telegram account.

func TestAProvenReplacementMovesTheFactor(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", telegram2fa.PurposeReplace)

	request, proof, err := h.Service.StartChatReplacement("user-1", h.LastCode())
	if err != nil {
		t.Fatalf("startChatReplacement: %v", err)
	}

	if request == nil {
		t.Fatalf("expected a request, got %#v", proof)
	}

	result, err := h.Service.CompleteDeepLink(request.Token, "777000222")
	if err != nil {
		t.Fatalf("completeDeepLink: %v", err)
	}

	if !result.OK {
		t.Fatalf("expected the move to apply, got %q", result.Error)
	}

	if got := h.Identity("user-1").ChatID; got != "777000222" {
		t.Fatalf("expected the new chat, got %q", got)
	}

	previous, err := h.Service.IdentityForChat("555000111")
	if err != nil {
		t.Fatalf("identityForChat: %v", err)
	}

	if previous != nil {
		t.Fatal("the old chat must be released")
	}
}

// The mark that authorises rebinding lives on the stored token. If it were
// taken from the resolving call instead, the proof step could be skipped by
// presenting an ordinary link token.
func TestAnOrdinaryTokenCannotMoveAVerifiedBinding(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")

	ordinary, err := h.Service.StartDeepLink("user-1")
	if err != nil {
		t.Fatalf("startDeepLink: %v", err)
	}

	result, _ := h.Service.CompleteDeepLink(ordinary.Token, "777000222")

	if result.Error != telegram2fa.ErrAlreadyLinked {
		t.Fatalf("expected already_linked, got %q", result.Error)
	}

	if got := h.Identity("user-1").ChatID; got != "555000111" {
		t.Fatalf("the original chat must stand, got %q", got)
	}
}

// A refused replacement must not cost the user the factor they already had.
// Releasing the old binding before checking the destination made a failed
// request strip the account of its second factor — which is what happened in
// an earlier revision of the PHP and Node packages.
func TestARefusedReplacementLeavesTheOriginalFactorIntact(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Seed("user-2", "777000222")
	h.Push("user-1", telegram2fa.PurposeReplace)

	request, _, err := h.Service.StartChatReplacement("user-1", h.LastCode())
	if err != nil || request == nil {
		t.Fatalf("startChatReplacement: %v", err)
	}

	result, _ := h.Service.CompleteDeepLink(request.Token, "777000222")

	if result.Error != telegram2fa.ErrAlreadyLinked {
		t.Fatalf("expected already_linked, got %q", result.Error)
	}

	// The other account keeps its chat...
	other, _ := h.Service.IdentityForChat("777000222")
	if other == nil || other.UserID != "user-2" {
		t.Fatal("the other account must keep its chat")
	}

	// ...and so does this one.
	if got := h.Identity("user-1").ChatID; got != "555000111" {
		t.Fatalf("the claimant must keep what it had, got %q", got)
	}
}

func TestARefusedReplacementDoesNotAnnounceOne(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Seed("user-2", "777000222")
	h.Push("user-1", telegram2fa.PurposeReplace)

	request, _, _ := h.Service.StartChatReplacement("user-1", h.LastCode())
	if request == nil {
		t.Fatal("expected a request")
	}

	h.Telegram.Reset()
	h.Service.CompleteDeepLink(request.Token, "777000222")

	// Telling the user their factor was removed when it was not is its own
	// small incident: they will go looking for an attacker.
	if got := len(h.Telegram.Sent()); got != 0 {
		t.Fatalf("expected silence, got %d messages", got)
	}
}

// Authority over a factor must not survive the factor.
func TestAReplacementTokenIsVoidAfterRecovery(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", telegram2fa.PurposeReplace)

	stale, _, err := h.Service.StartChatReplacement("user-1", h.LastCode())
	if err != nil || stale == nil {
		t.Fatalf("startChatReplacement: %v", err)
	}

	// The user loses their Telegram account and support recovers them.
	if _, err := h.Service.UnlinkAfterExternalProof("user-1", "verified out of band"); err != nil {
		t.Fatalf("recovery: %v", err)
	}

	fresh, _ := h.Service.StartDeepLink("user-1")
	h.Service.CompleteDeepLink(fresh.Token, "888000333")

	result, _ := h.Service.CompleteDeepLink(stale.Token, "999000444")

	if result.Error != telegram2fa.ErrInvalidToken {
		t.Fatalf("expected invalid_token, got %q", result.Error)
	}

	if got := h.Identity("user-1").ChatID; got != "888000333" {
		t.Fatalf("the recovered enrollment must survive, got %q", got)
	}
}

// What a timestamp fingerprint could not express: chat_id|linked_at repeats
// when the same chat is unlinked and relinked inside one second, reviving every
// token minted beforehand. The clock is never advanced in this test.
func TestUnlinkAndRelinkWithinOneSecondInvalidatesOldTokens(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", telegram2fa.PurposeReplace)

	stale, _, _ := h.Service.StartChatReplacement("user-1", h.LastCode())
	if stale == nil {
		t.Fatal("expected a request")
	}

	before := h.Clock.Now()

	h.Service.UnlinkAfterExternalProof("user-1", "user asked")
	fresh, _ := h.Service.StartDeepLink("user-1")
	h.Service.CompleteDeepLink(fresh.Token, "555000111")

	if h.Clock.Now() != before {
		t.Fatal("the whole sequence must be one second")
	}

	result, _ := h.Service.CompleteDeepLink(stale.Token, "999000444")

	if result.OK {
		t.Fatal("a token minted before the unlink must be void after the relink")
	}

	if got := h.Identity("user-1").ChatID; got != "555000111" {
		t.Fatalf("expected the relinked chat, got %q", got)
	}
}

// A code already delivered to the old chat is proof held by whoever still has
// that chat, so it cannot outlive the binding it was sent to.
func TestReplacementInvalidatesACodeSentToTheOldChat(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", telegram2fa.PurposeReplace)

	request, _, _ := h.Service.StartChatReplacement("user-1", h.LastCode())
	if request == nil {
		t.Fatal("expected a request")
	}

	h.Clock.Advance(121)
	h.Push("user-1", "login")
	inFlight := h.LastCode()

	if result, _ := h.Service.CompleteDeepLink(request.Token, "777000222"); !result.OK {
		t.Fatalf("the move should apply, got %q", result.Error)
	}

	if h.Verify("user-1", inFlight, "login").OK {
		t.Fatal("a code delivered to the replaced chat must not verify afterwards")
	}
}

// Preventing a stale record from being written back is best-effort; accepting
// one is impossible. So put the record back by hand — exactly what a lost race
// would do — and require that it still cannot authorise anything.
func TestAStaleRecordIsInertEvenWhenWrittenBack(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", "")
	code := h.LastCode()

	key := h.Config.Key("code", "user-1")

	record, err := h.Store.Get(key)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	// Revoke the enrollment the record belongs to.
	h.Service.UnlinkAfterExternalProof("user-1", "support recovery")
	fresh, _ := h.Service.StartDeepLink("user-1")
	h.Service.CompleteDeepLink(fresh.Token, "888000333")

	// Resurrect it.
	if err := h.Store.Put(key, record, h.Config.CodeTTL); err != nil {
		t.Fatalf("restoring: %v", err)
	}

	if h.Verify("user-1", code, "").OK {
		t.Fatal("a record from a superseded enrollment must be inert even if restored")
	}
}

func TestALoginCodeCannotAuthoriseAReplacement(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", telegram2fa.PurposeLogin)

	request, proof, err := h.Service.StartChatReplacement("user-1", h.LastCode())
	if err != nil {
		t.Fatalf("startChatReplacement: %v", err)
	}

	if request != nil || proof.OK {
		t.Fatal("a login code must not authorise a replacement")
	}
}

func TestTheGenerationSurvivesUnlinking(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")

	h.Service.UnlinkAfterExternalProof("user-1", "user asked")

	identity := h.Identity("user-1")

	// The row remains, carrying a new generation and no chat. This is what
	// lets revocation outlive the binding.
	if identity == nil {
		t.Fatal("the row must remain")
	}

	if identity.ChatID != "" || identity.IsVerified() {
		t.Fatalf("expected an unlinked row, got %#v", identity)
	}

	if identity.Generation == "" || identity.Generation == "gen-user-1" {
		t.Fatalf("the generation must change and persist, got %q", identity.Generation)
	}
}

func TestUnlinkingNotifiesTheChatAndClearsPending(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", telegram2fa.PurposeUnlink)
	code := h.LastCode()
	h.Telegram.Reset()

	result, err := h.Service.Unlink("user-1", code)
	if err != nil {
		t.Fatalf("unlink: %v", err)
	}

	if !result.OK {
		t.Fatalf("expected the unlink to apply, got %q", result.Error)
	}

	if got := len(h.Telegram.Sent()); got != 1 {
		t.Fatalf("expected one notice, got %d", got)
	}

	for _, key := range []string{"code", "cooldown"} {
		value, err := h.Store.Get(h.Config.Key(key, "user-1"))
		if err != nil {
			t.Fatalf("reading %s: %v", key, err)
		}

		if value != nil {
			t.Fatalf("%s must be cleared", key)
		}
	}
}
