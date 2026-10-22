package telegram2fa_test

import (
	"testing"

	telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
	"github.com/getkampe/telegram-2fa/packages/go/store"
)

// hookedIdentities fires a hook on the nth FindByUserID call.
//
// Counting reads is how a test targets one specific point in a sequence — the
// read that happens after a code has been accepted, say — without the core
// having to expose a seam for it.
type hookedIdentities struct {
	inner  *store.MemoryIdentityStore
	target int
	hook   func()
	reads  int
}

func (h *hookedIdentities) FindByUserID(userID string) (*telegram2fa.Identity, error) {
	h.reads++

	if h.hook != nil && h.reads == h.target {
		hook := h.hook
		h.hook = nil
		hook()
	}

	return h.inner.FindByUserID(userID)
}

func (h *hookedIdentities) FindByChatID(chatID string) (*telegram2fa.Identity, error) {
	return h.inner.FindByChatID(chatID)
}

func (h *hookedIdentities) Transition(
	userID, chatID, expected, next string,
) (*telegram2fa.Identity, error) {
	return h.inner.Transition(userID, chatID, expected, next)
}

// The window between the code being accepted and the token being written.
//
// An implementation that re-reads the enrollment after verifying and records
// *that* generation hands the token authority over whatever it finds — which,
// if a recovery landed in that window, is the recovered enrollment the user
// never proved. The generation written must be the one captured before
// verification, and a change during verification must be refused.
func TestRecoveryBetweenTheCodeAndTheTokenRefusesAuthorisation(t *testing.T) {
	clock := newFrozenClock()
	codes := store.NewMemoryCodeStore(clock)
	inner := store.NewMemoryIdentityStore(clock)
	identities := &hookedIdentities{inner: inner}
	telegram := &fakeTelegram{}

	config, err := telegram2fa.NewConfig(telegram2fa.Config{
		BotToken:      "123456789:AAFakeTokenForTestsOnly_0123456789abc",
		WebhookSecret: repeat("s", 48),
		HashPepper:    repeat("p", 48),
		BotUsername:   "kampe_test_bot",
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	service, err := telegram2fa.New(telegram2fa.Options{
		Config:     config,
		Store:      codes,
		Identities: identities,
		Telegram:   telegram,
		Messages:   telegram2fa.DefaultMessages{},
		Clock:      clock,
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}

	inner.Seed("victim", "555000111", "gen-initial")

	if _, err := service.Push("victim", telegram2fa.PurposeReplace); err != nil {
		t.Fatalf("push: %v", err)
	}

	code := codePattern.FindStringSubmatch(telegram.LastMessage())[1]

	// Fire the recovery on the identity read that happens after Verify.
	identities.reads = 0
	identities.target = 3
	identities.hook = func() {
		if _, err := service.UnlinkAfterExternalProof("victim", "support recovery"); err != nil {
			t.Errorf("recovery: %v", err)
		}

		fresh, err := service.StartDeepLink("victim")
		if err != nil {
			t.Errorf("startDeepLink: %v", err)

			return
		}

		if _, err := service.CompleteDeepLink(fresh.Token, "888000333"); err != nil {
			t.Errorf("completeDeepLink: %v", err)
		}
	}

	request, _, err := service.StartChatReplacement("victim", code)
	if err != nil {
		t.Fatalf("startChatReplacement: %v", err)
	}

	// Either refused outright, or the token it produced is inert. Silently
	// acquiring authority over the recovered enrollment is neither.
	if request != nil {
		result, err := service.CompleteDeepLink(request.Token, "999000444")
		if err != nil {
			t.Fatalf("completeDeepLink: %v", err)
		}

		if result.OK {
			t.Fatal("a token minted after recovery must not bind")
		}
	}

	identity, err := service.Identity("victim")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	if identity.ChatID != "888000333" {
		t.Fatalf("the recovered enrollment must survive, got %q", identity.ChatID)
	}
}
