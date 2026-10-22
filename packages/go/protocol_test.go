package telegram2fa_test

import (
	"testing"

	telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
)

// SPEC.md sections 4, 5 and 6.
func TestPushSendsACodeToTheLinkedChat(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")

	result := h.Push("user-1", "")

	if !result.OK {
		t.Fatalf("expected a send, got %q", result.Error)
	}

	if sent := h.Telegram.Sent(); len(sent) != 1 || sent[0].ChatID != "555000111" {
		t.Fatalf("expected one message to 555000111, got %#v", sent)
	}

	if code := h.LastCode(); len(code) != 6 {
		t.Fatalf("expected a six-digit code, got %q", code)
	}
}

func TestPushRefusesAnUnlinkedAccount(t *testing.T) {
	h := newHarness(t)

	if result := h.Push("nobody", ""); result.Error != telegram2fa.ErrNotLinked {
		t.Fatalf("expected not_linked, got %q", result.Error)
	}

	if len(h.Telegram.Sent()) != 0 {
		t.Fatal("nothing should have been sent")
	}
}

func TestAnUnverifiedLinkIsNotASecondFactor(t *testing.T) {
	h := newHarness(t)

	// A chat id present with no verification timestamp: a link started and
	// never finished.
	if _, err := h.Identities.Transition("user-1", "", "", "gen-partial"); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if result := h.Push("user-1", ""); result.Error != telegram2fa.ErrNotLinked {
		t.Fatalf("expected not_linked, got %q", result.Error)
	}
}

func TestASecondRequestInsideTheCooldownIsRefused(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")

	h.Push("user-1", "")
	second := h.Push("user-1", "")

	if second.Error != telegram2fa.ErrCooldown {
		t.Fatalf("expected cooldown, got %q", second.Error)
	}

	if got := second.RetryAfter(h.Clock.Now()); got != 120 {
		t.Fatalf("expected 120 seconds, got %d", got)
	}

	if len(h.Telegram.Sent()) != 1 {
		t.Fatal("only one code may be sent inside the cooldown")
	}
}

func TestARequestAfterTheCooldownIsAllowed(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")

	h.Push("user-1", "")
	h.Clock.Advance(121)

	if !h.Push("user-1", "").OK {
		t.Fatal("a send should be allowed once the cooldown lapses")
	}
}

// A code the user never received must not occupy the slot, or the account is
// stuck until the cooldown expires with no way to try again.
func TestAFailedDeliveryLeavesNoLiveCodeAndNoCooldown(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Telegram.FailNextSend(func() {})

	if result := h.Push("user-1", ""); result.Error != telegram2fa.ErrSendFailed {
		t.Fatalf("expected send_failed, got %q", result.Error)
	}

	if !h.Push("user-1", "").OK {
		t.Fatal("a retry should be possible immediately after a delivery failure")
	}
}

// A delivery failure handler that runs late must not throw away a code the user
// is already holding.
func TestALateDeliveryFailureCannotDiscardANewerChallenge(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")

	h.Telegram.FailNextSend(func() {
		h.Clock.Advance(121)
		h.Push("user-1", "login")
	})

	if result := h.Push("user-1", "login"); result.Error != telegram2fa.ErrSendFailed {
		t.Fatalf("expected send_failed, got %q", result.Error)
	}

	if !h.Verify("user-1", h.LastCode(), "login").OK {
		t.Fatal("the cleanup for a failed send must only discard its own challenge")
	}
}

// The single-key rule of SPEC.md section 4. An implementation that writes one
// key on push and reads another passes every pull-path test and silently fails
// every real push.
func TestAPushedAndAPulledCodeVerifyThroughTheSameCall(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")

	h.Push("user-1", "")

	if !h.Verify("user-1", h.LastCode(), "").OK {
		t.Fatal("a pushed code must verify")
	}

	h.Clock.Advance(121)

	if _, err := h.Service.Pull("555000111"); err != nil {
		t.Fatalf("pull: %v", err)
	}

	if !h.Verify("user-1", h.LastCode(), "").OK {
		t.Fatal("a pulled code must verify through the same call")
	}
}

func TestCodesAreStoredHashedAndBoundToTheAccount(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Seed("user-2", "777000222")
	h.Push("user-1", "")

	code := h.LastCode()

	record, err := h.Store.Get(h.Config.Key("code", "user-1"))
	if err != nil {
		t.Fatalf("reading the record: %v", err)
	}

	stored, ok := record.(map[string]any)
	if !ok {
		t.Fatalf("expected a record, got %#v", record)
	}

	if stored["hash"] == code {
		t.Fatal("the code must not be stored in plaintext")
	}

	// Transplant user-1's record onto user-2, as a store-level attacker with a
	// known code would.
	if err := h.Store.Put(h.Config.Key("code", "user-2"), stored, h.Config.CodeTTL); err != nil {
		t.Fatalf("transplanting: %v", err)
	}

	if h.Verify("user-2", code, "").OK {
		t.Fatal("a digest must not verify against a different account")
	}

	if !h.Verify("user-1", code, "").OK {
		t.Fatal("and must still verify against its own")
	}
}

func TestACodeWorksOnlyOnce(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", "")
	code := h.LastCode()

	if !h.Verify("user-1", code, "").OK {
		t.Fatal("the first verification must pass")
	}

	replay := h.Verify("user-1", code, "")

	if replay.OK || replay.Error != telegram2fa.ErrExpired {
		t.Fatalf("a verified code must not verify again, got %#v", replay)
	}
}

func TestTheAttemptBudgetKillsTheCode(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", "")
	code := h.LastCode()
	wrong := h.WrongCode(code)

	for i := 0; i < 4; i++ {
		if got := h.Verify("user-1", wrong, "").Error; got != telegram2fa.ErrInvalid {
			t.Fatalf("attempt %d: expected invalid, got %q", i+1, got)
		}
	}

	if got := h.Verify("user-1", wrong, "").Error; got != telegram2fa.ErrTooManyAttempts {
		t.Fatalf("expected too_many_attempts, got %q", got)
	}

	// And the real code is dead too, which is the point: the budget belongs to
	// the code, not to the attacker.
	if h.Verify("user-1", code, "").OK {
		t.Fatal("the code must be destroyed with its budget")
	}
}

func TestAWrongGuessDoesNotExtendTheCodesLife(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", "")
	code := h.LastCode()

	h.Clock.Advance(200)
	h.Verify("user-1", h.WrongCode(code), "")

	h.Clock.Advance(101) // 301s since issue

	if got := h.Verify("user-1", code, "").Error; got != telegram2fa.ErrExpired {
		t.Fatalf("expected expired, got %q", got)
	}
}

func TestWhitespaceAroundAPastedCodeIsTolerated(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", "")

	if !h.Verify("user-1", " "+h.LastCode()+"\n", "").OK {
		t.Fatal("a pasted code with whitespace must verify")
	}
}

// SPEC.md 4.1, 4.2 and 5 — purpose binding.
func TestAPushedCodeDoesNotSatisfyAnotherPurpose(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", telegram2fa.PurposeLogin)

	if h.Verify("user-1", h.LastCode(), "withdrawal").OK {
		t.Fatal("a login code must not approve a withdrawal")
	}
}

func TestOmittingThePurposeMeansLoginNotAWildcard(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", "withdrawal")

	if h.Verify("user-1", h.LastCode(), "").OK {
		t.Fatal("an empty purpose must mean login, never anything")
	}
}

func TestAnOnDemandCodeSatisfiesAnyPurpose(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")

	if _, err := h.Service.Pull("555000111"); err != nil {
		t.Fatalf("pull: %v", err)
	}

	if !h.Verify("user-1", h.LastCode(), "withdrawal").OK {
		t.Fatal("a code the user fetched deliberately is general-purpose")
	}
}

func TestTheOnDemandExemptionCanBeNarrowed(t *testing.T) {
	h := newHarness(t, func(c *telegram2fa.Config) {
		c.OnDemandSatisfies = []string{"login"}
	})
	h.Seed("user-1", "555000111")

	if _, err := h.Service.Pull("555000111"); err != nil {
		t.Fatalf("pull: %v", err)
	}

	if !h.Verify("user-1", h.LastCode(), "login").OK {
		t.Fatal("still fine for signing in")
	}

	h.Clock.Advance(121)

	if _, err := h.Service.Pull("555000111"); err != nil {
		t.Fatalf("pull: %v", err)
	}

	if h.Verify("user-1", h.LastCode(), "withdrawal").OK {
		t.Fatal("no longer a way to approve a payout")
	}
}

func TestAPurposeMismatchReportsInvalidAndSpendsAnAttempt(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", telegram2fa.PurposeLogin)
	code := h.LastCode()

	first := h.Verify("user-1", code, "withdrawal")

	// Reporting the mismatch distinctly would tell a caller that a live code
	// exists for a different step, which it has not proved it may know.
	if first.Error != telegram2fa.ErrInvalid || first.AttemptsRemaining != 4 {
		t.Fatalf("expected invalid with 4 left, got %#v", first)
	}

	if got := h.Verify("user-1", code, "withdrawal").AttemptsRemaining; got != 3 {
		t.Fatalf("the mismatch path must be budgeted, got %d left", got)
	}
}

func TestUnlinkingRequiresTheRightPurpose(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")
	h.Push("user-1", telegram2fa.PurposeLogin)

	result, err := h.Service.Unlink("user-1", h.LastCode())
	if err != nil {
		t.Fatalf("unlink: %v", err)
	}

	if result.OK {
		t.Fatal("a login code must not remove the factor")
	}

	if !h.IsLinked("user-1") {
		t.Fatal("and the factor must still be there")
	}
}

func TestUnlinkingAcceptsACodeTheUserFetched(t *testing.T) {
	h := newHarness(t)
	h.Seed("user-1", "555000111")

	if _, err := h.Service.Pull("555000111"); err != nil {
		t.Fatalf("pull: %v", err)
	}

	result, err := h.Service.Unlink("user-1", h.LastCode())
	if err != nil {
		t.Fatalf("unlink: %v", err)
	}

	if !result.OK {
		t.Fatalf("an on-demand code must satisfy an unlink, got %q", result.Error)
	}

	if h.IsLinked("user-1") {
		t.Fatal("the factor must be gone")
	}
}

// SPEC.md sections 2 and 3 — linking.
func TestTheDeeplinkFlowLinksTheAccount(t *testing.T) {
	h := newHarness(t)

	request, err := h.Service.StartDeepLink("user-1")
	if err != nil {
		t.Fatalf("startDeepLink: %v", err)
	}

	if want := "https://t.me/kampe_test_bot?start=" + request.Token; request.URL != want {
		t.Fatalf("expected %q, got %q", want, request.URL)
	}

	result, err := h.Service.CompleteDeepLink(request.Token, "555000111")
	if err != nil {
		t.Fatalf("completeDeepLink: %v", err)
	}

	if !result.OK || !h.IsLinked("user-1") {
		t.Fatalf("expected a link, got %#v", result)
	}
}

func TestADeeplinkTokenIsSingleUse(t *testing.T) {
	h := newHarness(t)

	request, _ := h.Service.StartDeepLink("user-1")
	h.Service.CompleteDeepLink(request.Token, "555000111")

	// A second presentation from a different chat: the obvious attack if the
	// token survives, since the token travels through a chat message.
	replay, err := h.Service.CompleteDeepLink(request.Token, "999999999")
	if err != nil {
		t.Fatalf("completeDeepLink: %v", err)
	}

	if replay.Error != telegram2fa.ErrInvalidToken {
		t.Fatalf("expected invalid_token, got %q", replay.Error)
	}
}

func TestAnExpiredDeeplinkTokenIsRefused(t *testing.T) {
	h := newHarness(t)

	request, _ := h.Service.StartDeepLink("user-1")
	h.Clock.Advance(601)

	result, _ := h.Service.CompleteDeepLink(request.Token, "555000111")

	if result.Error != telegram2fa.ErrInvalidToken {
		t.Fatalf("expected invalid_token, got %q", result.Error)
	}
}

func TestTheLinkTokenIsNotStoredInPlaintext(t *testing.T) {
	h := newHarness(t)

	request, _ := h.Service.StartDeepLink("user-1")

	stored, err := h.Store.Get(h.Config.Key("link", request.Token))
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	if stored != nil {
		t.Fatal("the raw token must not be a store key")
	}

	result, _ := h.Service.CompleteDeepLink(request.Token, "555000111")

	if !result.OK {
		t.Fatal("and the token must still resolve")
	}
}

func TestThePasteFlowLinksTheAccount(t *testing.T) {
	h := newHarness(t)

	request, err := h.Service.StartPasteLink("555000111")
	if err != nil {
		t.Fatalf("startPasteLink: %v", err)
	}

	// The paste flow's key is derived from the code, so all outstanding codes
	// share one namespace. Eight base32 characters is 40 bits; six digits
	// would be guessable.
	if len(request.Token) != 8 {
		t.Fatalf("expected an eight-character code, got %q", request.Token)
	}

	result, err := h.Service.CompletePasteLink("user-1", request.Token)
	if err != nil {
		t.Fatalf("completePasteLink: %v", err)
	}

	if !result.OK || !h.IsLinked("user-1") {
		t.Fatalf("expected a link, got %#v", result)
	}
}

func TestAPasteCodeIsAcceptedInLowerCase(t *testing.T) {
	h := newHarness(t)

	request, _ := h.Service.StartPasteLink("555000111")

	result, _ := h.Service.CompletePasteLink("user-1", lower(request.Token))

	if !result.OK {
		t.Fatalf("a lower-case paste code must resolve, got %q", result.Error)
	}
}

// One Telegram account as the factor for several accounts means one compromised
// Telegram account compromises all of them.
func TestAChatCannotBecomeTheFactorForASecondAccount(t *testing.T) {
	h := newHarness(t)

	first, _ := h.Service.StartDeepLink("user-1")
	h.Service.CompleteDeepLink(first.Token, "555000111")

	second, _ := h.Service.StartDeepLink("user-2")
	result, _ := h.Service.CompleteDeepLink(second.Token, "555000111")

	if result.Error != telegram2fa.ErrAlreadyLinked {
		t.Fatalf("expected already_linked, got %q", result.Error)
	}

	if h.IsLinked("user-2") {
		t.Fatal("the second account must not be linked")
	}
}

func TestAnAccountCannotBeMovedWithoutAReplacement(t *testing.T) {
	h := newHarness(t)

	first, _ := h.Service.StartDeepLink("user-1")
	h.Service.CompleteDeepLink(first.Token, "555000111")

	second, _ := h.Service.StartDeepLink("user-1")
	result, _ := h.Service.CompleteDeepLink(second.Token, "777000222")

	if result.Error != telegram2fa.ErrAlreadyLinked {
		t.Fatalf("expected already_linked, got %q", result.Error)
	}

	if got := h.Identity("user-1").ChatID; got != "555000111" {
		t.Fatalf("the original chat must stand, got %q", got)
	}
}

func TestRelinkingTheSameChatIsIdempotent(t *testing.T) {
	h := newHarness(t)

	first, _ := h.Service.StartDeepLink("user-1")
	h.Service.CompleteDeepLink(first.Token, "555000111")

	// A user who taps the same link twice, or whose first confirmation was
	// lost, should see success rather than a conflict.
	second, _ := h.Service.StartDeepLink("user-1")
	result, _ := h.Service.CompleteDeepLink(second.Token, "555000111")

	if !result.OK {
		t.Fatalf("expected idempotent success, got %q", result.Error)
	}
}

func lower(s string) string {
	out := []byte(s)

	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		}
	}

	return string(out)
}
