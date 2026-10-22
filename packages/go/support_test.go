package telegram2fa_test

import (
	"regexp"
	"sync"
	"testing"
	"time"

	telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
	"github.com/getkampe/telegram-2fa/packages/go/store"
)

var codePattern = regexp.MustCompile(`<code>([^<]+)</code>`)

// frozenClock moves only when you move it.
type frozenClock struct {
	mu  sync.Mutex
	now int64
}

func newFrozenClock() *frozenClock { return &frozenClock{now: 1_700_000_000} }

func (c *frozenClock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *frozenClock) Advance(seconds int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now += seconds
}

// fakeTelegram records what it was asked to send.
type fakeTelegram struct {
	mu                sync.Mutex
	sent              []sentMessage
	answered          []string
	shouldFailSending bool
	duringNextFailure func()
}

type sentMessage struct {
	ChatID string
	Text   string
}

// FailNextSend fails the next send, running during while it is "in flight".
//
// Models a send that blocks long enough for the world to move on — the cooldown
// lapsing and another challenge being issued — before the failure is reported
// and its cleanup runs.
func (f *fakeTelegram) FailNextSend(during func()) {
	f.mu.Lock()
	f.shouldFailSending = true
	f.duringNextFailure = during
	f.mu.Unlock()
}

func (f *fakeTelegram) SendMessage(
	chatID, text string, _ [][]telegram2fa.InlineButton,
) (bool, error) {
	f.mu.Lock()

	if f.shouldFailSending {
		during := f.duringNextFailure

		if during != nil {
			// One-shot: the hook models a single slow, failing send, and the
			// sends it triggers must succeed.
			f.duringNextFailure = nil
			f.shouldFailSending = false
			f.mu.Unlock()
			during()

			return false, nil
		}

		f.mu.Unlock()

		return false, nil
	}

	f.sent = append(f.sent, sentMessage{ChatID: chatID, Text: text})
	f.mu.Unlock()

	return true, nil
}

func (f *fakeTelegram) AnswerCallbackQuery(id, _ string) (bool, error) {
	f.mu.Lock()
	f.answered = append(f.answered, id)
	f.mu.Unlock()

	return true, nil
}

func (f *fakeTelegram) GetMe() (map[string]any, error) {
	return map[string]any{"username": "kampe_test_bot"}, nil
}

func (f *fakeTelegram) SetWebhook(string, string, []string) (bool, error) { return true, nil }
func (f *fakeTelegram) DeleteWebhook() (bool, error)                      { return true, nil }

func (f *fakeTelegram) Sent() []sentMessage {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]sentMessage(nil), f.sent...)
}

func (f *fakeTelegram) LastMessage() string {
	sent := f.Sent()

	if len(sent) == 0 {
		return ""
	}

	return sent[len(sent)-1].Text
}

func (f *fakeTelegram) Answered() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.answered...)
}

func (f *fakeTelegram) Reset() {
	f.mu.Lock()
	f.sent = nil
	f.answered = nil
	f.mu.Unlock()
}

// harness is a fully wired service on in-memory parts.
type harness struct {
	t          *testing.T
	Clock      *frozenClock
	Store      *store.MemoryCodeStore
	Identities *store.MemoryIdentityStore
	Telegram   *fakeTelegram
	Config     *telegram2fa.Config
	Service    *telegram2fa.Service
}

func newHarness(t *testing.T, mutate ...func(*telegram2fa.Config)) *harness {
	t.Helper()

	clock := newFrozenClock()
	codeStore := store.NewMemoryCodeStore(clock)
	identities := store.NewMemoryIdentityStore(clock)
	telegram := &fakeTelegram{}

	raw := telegram2fa.Config{
		BotToken:      "123456789:AAFakeTokenForTestsOnly_0123456789abc",
		WebhookSecret: repeat("s", 48),
		HashPepper:    repeat("p", 48),
		BotUsername:   "kampe_test_bot",
		AppName:       "Kampe",
		DedupeUpdates: true,
	}

	for _, apply := range mutate {
		apply(&raw)
	}

	config, err := telegram2fa.NewConfig(raw)
	if err != nil {
		t.Fatalf("building the config: %v", err)
	}

	service, err := telegram2fa.New(telegram2fa.Options{
		Config:     config,
		Store:      codeStore,
		Identities: identities,
		Telegram:   telegram,
		Messages:   telegram2fa.DefaultMessages{},
		Clock:      clock,
	})
	if err != nil {
		t.Fatalf("building the service: %v", err)
	}

	return &harness{
		t:          t,
		Clock:      clock,
		Store:      codeStore,
		Identities: identities,
		Telegram:   telegram,
		Config:     config,
		Service:    service,
	}
}

// Seed stores a verified enrollment without going through a link flow.
func (h *harness) Seed(userID, chatID string) telegram2fa.Identity {
	return h.Identities.Seed(userID, chatID, "gen-"+userID)
}

// LastCode recovers the code from the most recent outgoing message, because the
// library deliberately never returns it.
func (h *harness) LastCode() string {
	match := codePattern.FindStringSubmatch(h.Telegram.LastMessage())

	if len(match) < 2 {
		return ""
	}

	return match[1]
}

func (h *harness) WrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}

	return "000000"
}

// Push is a convenience that fails the test on a transport error, so the body
// of each test reads as the protocol rather than as error plumbing.
func (h *harness) Push(userID, purpose string) telegram2fa.ChallengeResult {
	h.t.Helper()

	result, err := h.Service.Push(userID, purpose)
	if err != nil {
		h.t.Fatalf("push: %v", err)
	}

	return result
}

func (h *harness) Verify(userID, code, purpose string) telegram2fa.VerificationResult {
	h.t.Helper()

	result, err := h.Service.Verify(userID, code, purpose)
	if err != nil {
		h.t.Fatalf("verify: %v", err)
	}

	return result
}

func (h *harness) IsLinked(userID string) bool {
	h.t.Helper()

	linked, err := h.Service.IsLinked(userID)
	if err != nil {
		h.t.Fatalf("isLinked: %v", err)
	}

	return linked
}

func (h *harness) Identity(userID string) *telegram2fa.Identity {
	h.t.Helper()

	identity, err := h.Service.Identity(userID)
	if err != nil {
		h.t.Fatalf("identity: %v", err)
	}

	return identity
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))

	for i := 0; i < n; i++ {
		out = append(out, s...)
	}

	return string(out)
}

// race runs work on n goroutines released simultaneously.
//
// The WaitGroup barrier is what makes it meaningful: without it the first
// goroutine usually finishes before the last one starts, and the test would
// pass against a broken implementation most of the time.
func race[T any](n int, work func(int) T) []T {
	var start sync.WaitGroup
	var done sync.WaitGroup

	start.Add(1)
	results := make([]T, n)

	for i := 0; i < n; i++ {
		done.Add(1)

		go func(index int) {
			defer done.Done()
			start.Wait()

			results[index] = work(index)
		}(i)
	}

	start.Done()
	done.Wait()

	return results
}

var _ = time.Second
