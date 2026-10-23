package webhook_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
	"github.com/getkampe/telegram-2fa/packages/go/store"
	"github.com/getkampe/telegram-2fa/packages/go/webhook"
)

const secret = "ssssssssssssssssssssssssssssssssssssssssssssssss"

func testConfig(t *testing.T, mutate ...func(*telegram2fa.Config)) *telegram2fa.Config {
	t.Helper()

	raw := telegram2fa.Config{
		BotToken:      "123456789:AAFakeTokenForTestsOnly_0123456789abc",
		WebhookSecret: secret,
		HashPepper:    strings.Repeat("p", 48),
		BotUsername:   "kampe_test_bot",
		DedupeUpdates: true,
	}

	for _, apply := range mutate {
		apply(&raw)
	}

	config, err := telegram2fa.NewConfig(raw)
	if err != nil {
		t.Fatalf("building the config: %v", err)
	}

	return config
}

// SPEC.md section 7. The check that matters most: without it the webhook
// accepts a forged assertion that any chat id is asking for a code.
func TestVerifierAcceptsTheMatchingSecret(t *testing.T) {
	if !webhook.NewVerifier(testConfig(t)).Accepts(secret, "") {
		t.Fatal("the matching secret must be accepted")
	}
}

func TestVerifierRejectsAWrongOrMissingSecret(t *testing.T) {
	verifier := webhook.NewVerifier(testConfig(t))

	for _, value := range []string{"", strings.Repeat("x", 48)} {
		if verifier.Accepts(value, "") {
			t.Fatalf("%q must be rejected", value)
		}
	}
}

// A prefix or an extension of the secret must not be accepted. Truncating or
// length-insensitive comparisons are the classic way this gets written wrong.
func TestVerifierRejectsAPrefixOrExtension(t *testing.T) {
	verifier := webhook.NewVerifier(testConfig(t))

	for _, value := range []string{strings.Repeat("s", 47), strings.Repeat("s", 49)} {
		if verifier.Accepts(value, "") {
			t.Fatalf("%q must be rejected", value)
		}
	}
}

func TestVerifierIPRestriction(t *testing.T) {
	verifier := webhook.NewVerifier(testConfig(t, func(c *telegram2fa.Config) {
		c.RestrictWebhookIPs = true
	}))

	for _, address := range []string{"149.154.160.1", "149.154.175.254", "91.108.4.10"} {
		if !verifier.Accepts(secret, address) {
			t.Fatalf("%s is a Telegram address", address)
		}
	}

	for _, address := range []string{"8.8.8.8", "149.154.176.1", "127.0.0.1", "", "nonsense"} {
		if verifier.Accepts(secret, address) {
			t.Fatalf("%s must be rejected", address)
		}
	}
}

// Off by default because behind a proxy the peer address is the proxy, so the
// check would be either useless or actively misleading.
func TestVerifierIPRestrictionIsOffByDefault(t *testing.T) {
	if !webhook.NewVerifier(testConfig(t)).Accepts(secret, "8.8.8.8") {
		t.Fatal("IP restriction must be opt-in")
	}
}

func TestVerifierToleratesAHostPort(t *testing.T) {
	verifier := webhook.NewVerifier(testConfig(t, func(c *telegram2fa.Config) {
		c.RestrictWebhookIPs = true
	}))

	// http.Request.RemoteAddr carries a port.
	if !verifier.Accepts(secret, "149.154.160.1:443") {
		t.Fatal("a host:port peer address must still be understood")
	}
}

// --------------------------------------------------------------- handler

type harness struct {
	t          *testing.T
	clock      *testClock
	store      *store.MemoryCodeStore
	identities *store.MemoryIdentityStore
	telegram   *recorder
	config     *telegram2fa.Config
	service    *telegram2fa.Service
	handler    *webhook.Handler
	nextUpdate int64
}

type testClock struct{ now int64 }

func (c *testClock) Now() int64 { return c.now }

type recorder struct {
	sent     []string
	answered []string
}

func (r *recorder) SendMessage(_, text string, _ [][]telegram2fa.InlineButton) (bool, error) {
	r.sent = append(r.sent, text)

	return true, nil
}

func (r *recorder) AnswerCallbackQuery(id, _ string) (bool, error) {
	r.answered = append(r.answered, id)

	return true, nil
}

func (r *recorder) GetMe() (map[string]any, error)                    { return nil, nil }
func (r *recorder) SetWebhook(string, string, []string) (bool, error) { return true, nil }
func (r *recorder) DeleteWebhook() (bool, error)                      { return true, nil }

func (r *recorder) last() string {
	if len(r.sent) == 0 {
		return ""
	}

	return r.sent[len(r.sent)-1]
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	clock := &testClock{now: 1_700_000_000}
	codes := store.NewMemoryCodeStore(clock)
	identities := store.NewMemoryIdentityStore(clock)
	telegram := &recorder{}
	config := testConfig(t)

	service, err := telegram2fa.New(telegram2fa.Options{
		Config:     config,
		Store:      codes,
		Identities: identities,
		Telegram:   telegram,
		Messages:   telegram2fa.DefaultMessages{},
		Clock:      clock,
	})
	if err != nil {
		t.Fatalf("building the service: %v", err)
	}

	handler := webhook.NewHandler(webhook.HandlerOptions{
		Service:  service,
		Config:   config,
		Store:    codes,
		Telegram: telegram,
		Messages: telegram2fa.DefaultMessages{},
		Clock:    clock,
	})

	return &harness{
		t:          t,
		clock:      clock,
		store:      codes,
		identities: identities,
		telegram:   telegram,
		config:     config,
		service:    service,
		handler:    handler,
		nextUpdate: 1000,
	}
}

func (h *harness) message(text, chatID string) webhook.Update {
	h.nextUpdate++

	raw := `{"update_id":` + itoa(h.nextUpdate) +
		`,"message":{"message_id":1,"text":` + quote(text) +
		`,"chat":{"id":` + quote(chatID) + `,"type":"private"}}}`

	var update webhook.Update

	if err := json.Unmarshal([]byte(raw), &update); err != nil {
		h.t.Fatalf("building an update: %v", err)
	}

	return update
}

func TestStartWithAPayloadLinksTheAccount(t *testing.T) {
	h := newHarness(t)

	request, err := h.service.StartDeepLink("user-1")
	if err != nil {
		t.Fatalf("startDeepLink: %v", err)
	}

	if _, err := h.handler.Handle(h.message("/start "+request.Token, "555000111")); err != nil {
		t.Fatalf("handle: %v", err)
	}

	linked, _ := h.service.IsLinked("user-1")

	if !linked {
		t.Fatal("the account should be linked")
	}

	if !strings.Contains(h.telegram.last(), "second factor") {
		t.Fatalf("expected a confirmation, got %q", h.telegram.last())
	}
}

func TestCodeIssuesACodeForALinkedChat(t *testing.T) {
	h := newHarness(t)
	h.identities.Seed("user-1", "555000111", "gen-1")

	if _, err := h.handler.Handle(h.message("/code", "555000111")); err != nil {
		t.Fatalf("handle: %v", err)
	}

	if !strings.Contains(h.telegram.last(), "<code>") {
		t.Fatalf("expected a code, got %q", h.telegram.last())
	}
}

func TestCodeTellsAnUnlinkedChatHowToLink(t *testing.T) {
	h := newHarness(t)

	h.handler.Handle(h.message("/code", "555000111"))

	if !strings.Contains(h.telegram.last(), "not linked") {
		t.Fatalf("expected guidance, got %q", h.telegram.last())
	}
}

// Telegram retries an update it believes was not delivered, and delivers
// concurrently. Without a claim a retried /code mints a second code and resets
// the cooldown.
func TestARepeatedUpdateIDIsDropped(t *testing.T) {
	h := newHarness(t)
	h.identities.Seed("user-1", "555000111", "gen-1")
	update := h.message("/code", "555000111")

	first, err := h.handler.Handle(update)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	second, err := h.handler.Handle(update)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	if !first || second {
		t.Fatalf("expected the retry to be dropped, got %v then %v", first, second)
	}

	if got := len(h.telegram.sent); got != 1 {
		t.Fatalf("expected one message, got %d", got)
	}
}

// An update marked done before its work succeeds is an update permanently
// lost: the retry arrives, sees the marker, and drops it.
func TestTheClaimIsReleasedWhenHandlingFails(t *testing.T) {
	h := newHarness(t)
	h.identities.Seed("user-1", "555000111", "gen-1")

	h.handler.On("boom", func(string, string) error {
		return errors.New("downstream failure")
	})

	update := h.message("/boom", "555000111")

	if _, err := h.handler.Handle(update); err == nil {
		t.Fatal("expected the failure to surface")
	}

	retried := false
	h.handler.On("boom", func(string, string) error {
		retried = true

		return nil
	})

	if _, err := h.handler.Handle(update); err != nil {
		t.Fatalf("the retry should succeed: %v", err)
	}

	if !retried {
		t.Fatal("Telegram's retry of a failed update must be processed")
	}
}

// Otherwise the bot hands out verification codes in front of every member.
func TestGroupChatsAreIgnored(t *testing.T) {
	h := newHarness(t)
	h.identities.Seed("user-1", "-1001234567890", "gen-1")

	update := h.message("/code", "-1001234567890")
	update.Message.Chat.Type = "supergroup"

	h.handler.Handle(update)

	if got := len(h.telegram.sent); got != 0 {
		t.Fatalf("expected silence in a group, got %d messages", got)
	}
}

// Codes travel application-to-user, never user-to-bot, so free text is not a
// code to check.
func TestFreeTextIsNotTreatedAsACode(t *testing.T) {
	h := newHarness(t)
	h.identities.Seed("user-1", "555000111", "gen-1")

	h.handler.Handle(h.message("123456", "555000111"))

	if !strings.Contains(h.telegram.last(), "do not know that command") {
		t.Fatalf("expected a nudge, got %q", h.telegram.last())
	}
}

func TestACommandAddressedToTheBotIsUnderstood(t *testing.T) {
	h := newHarness(t)
	h.identities.Seed("user-1", "555000111", "gen-1")

	h.handler.Handle(h.message("/code@kampe_test_bot", "555000111"))

	if !strings.Contains(h.telegram.last(), "<code>") {
		t.Fatalf("expected a code, got %q", h.telegram.last())
	}
}

// Whoever holds the phone can already read the codes; letting them also remove
// the factor with no session and no password turns a stolen phone into a
// permanently single-factor account.
func TestUnlinkAnswersWithInstructionsAndDoesNotUnlink(t *testing.T) {
	h := newHarness(t)
	h.identities.Seed("user-1", "555000111", "gen-1")

	h.handler.Handle(h.message("/unlink", "555000111"))

	if !strings.Contains(h.telegram.last(), "cannot be done from the chat") {
		t.Fatalf("expected instructions, got %q", h.telegram.last())
	}

	linked, _ := h.service.IsLinked("user-1")

	if !linked {
		t.Fatal("the bot must not remove the factor")
	}
}

func TestAnApplicationCommandCanBeRegistered(t *testing.T) {
	h := newHarness(t)

	var seen [2]string
	h.handler.On("balance", func(chatID, argument string) error {
		seen = [2]string{chatID, argument}

		return nil
	})

	h.handler.Handle(h.message("/balance usd", "555000111"))

	if seen[0] != "555000111" || seen[1] != "usd" {
		t.Fatalf("expected the chat and argument, got %#v", seen)
	}
}

func TestACallbackQueryIsAcknowledgedThenHandled(t *testing.T) {
	h := newHarness(t)
	h.identities.Seed("user-1", "555000111", "gen-1")

	raw := `{"update_id":991,"callback_query":{"id":"cb-1","data":"code",` +
		`"message":{"chat":{"id":"555000111","type":"private"}}}}`

	var update webhook.Update

	if err := json.Unmarshal([]byte(raw), &update); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	h.handler.Handle(update)

	if len(h.telegram.answered) != 1 || h.telegram.answered[0] != "cb-1" {
		t.Fatalf("the query must be acknowledged, got %#v", h.telegram.answered)
	}

	if !strings.Contains(h.telegram.last(), "<code>") {
		t.Fatalf("expected a code, got %q", h.telegram.last())
	}
}

func TestANumericChatIDIsUnderstood(t *testing.T) {
	h := newHarness(t)
	h.identities.Seed("user-1", "555000111", "gen-1")

	// Telegram sends the chat id as a JSON number, which decodes to float64.
	raw := `{"update_id":1234,"message":{"message_id":1,"text":"/code",` +
		`"chat":{"id":555000111,"type":"private"}}}`

	var update webhook.Update

	if err := json.Unmarshal([]byte(raw), &update); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	h.handler.Handle(update)

	if !strings.Contains(h.telegram.last(), "<code>") {
		t.Fatalf("a numeric chat id must resolve, got %q", h.telegram.last())
	}
}

// --------------------------------------------------------- conformance

// SPEC.md section 9, against the shared fixture in /conformance.
//
// The repository claims the implementations can share one bot and one store.
// That is a claim about field names and hash construction, and it only means
// anything if every implementation reads the same committed records.
func TestRecordsWrittenByAnotherImplementationAreUnderstood(t *testing.T) {
	path := filepath.Join("..", "..", "..", "conformance", "records.json")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s: %v", path, err)
	}

	var fixture struct {
		Config struct {
			KeyPrefix     string `json:"key_prefix"`
			HashAlgorithm string `json:"hash_algorithm"`
			HashPepper    string `json:"hash_pepper"`
		} `json:"config"`
		Now        int64 `json:"now"`
		CodeRecord struct {
			Key           string         `json:"key"`
			UserID        string         `json:"user_id"`
			Enrollment    string         `json:"enrollment"`
			PlaintextCode string         `json:"plaintext_code"`
			Value         map[string]any `json:"value"`
		} `json:"code_record"`
		DeeplinkRecord struct {
			Key    string         `json:"key"`
			Token  string         `json:"token"`
			UserID string         `json:"user_id"`
			Value  map[string]any `json:"value"`
		} `json:"deeplink_record"`
	}

	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}

	clock := &testClock{now: fixture.Now}
	codes := store.NewMemoryCodeStore(clock)
	identities := store.NewMemoryIdentityStore(clock)

	config, err := telegram2fa.NewConfig(telegram2fa.Config{
		BotToken:      "123456789:AAFakeTokenForTestsOnly_0123456789abc",
		WebhookSecret: secret,
		HashPepper:    fixture.Config.HashPepper,
		KeyPrefix:     fixture.Config.KeyPrefix,
		HashAlgorithm: fixture.Config.HashAlgorithm,
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	service, err := telegram2fa.New(telegram2fa.Options{
		Config:     config,
		Store:      codes,
		Identities: identities,
		Telegram:   &recorder{},
		Messages:   telegram2fa.DefaultMessages{},
		Clock:      clock,
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}

	// Seed the exact enrollment the fixture's challenge belongs to: a
	// challenge from a superseded enrollment is refused, so interop depends on
	// agreeing about that field too.
	identities.Seed(fixture.CodeRecord.UserID, "555000111", fixture.CodeRecord.Enrollment)

	if err := codes.Put(fixture.CodeRecord.Key, fixture.CodeRecord.Value, 5*time.Minute); err != nil {
		t.Fatalf("seeding the record: %v", err)
	}

	result, err := service.Verify(
		fixture.CodeRecord.UserID, fixture.CodeRecord.PlaintextCode, "withdrawal")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if !result.OK {
		t.Fatalf("a record in the shared wire format must verify, got %q", result.Error)
	}

	// And a deeplink record written elsewhere must resolve here.
	if err := codes.Put(
		fixture.DeeplinkRecord.Key, fixture.DeeplinkRecord.Value, 10*time.Minute); err != nil {
		t.Fatalf("seeding the deeplink: %v", err)
	}

	link, err := service.CompleteDeepLink(fixture.DeeplinkRecord.Token, "888000333")
	if err != nil {
		t.Fatalf("completeDeepLink: %v", err)
	}

	if !link.OK {
		t.Fatalf("a deeplink record in the shared format must resolve, got %q", link.Error)
	}
}

// A store is not obliged to preserve numeric types: JSON round-trips an int as
// a float64, and the PHP package's Redis adapter returns bare numerics as
// strings. The cooldown is the one bare integer, so it must be coerced.
func TestACooldownWrittenAsAStringIsStillUnderstood(t *testing.T) {
	h := newHarness(t)
	h.identities.Seed("user-1", "555000111", "gen-1")

	if _, err := h.service.Push("user-1", ""); err != nil {
		t.Fatalf("push: %v", err)
	}

	key := h.config.Key("cooldown", "user-1")

	held, err := h.store.Get(key)
	if err != nil {
		t.Fatalf("reading the cooldown: %v", err)
	}

	// Rewrite it the way another implementation's store would hand it over.
	if err := h.store.Put(key, itoa(toInt64(held)), 2*time.Minute); err != nil {
		t.Fatalf("rewriting: %v", err)
	}

	result, err := h.service.Push("user-1", "")
	if err != nil {
		t.Fatalf("push: %v", err)
	}

	if result.Error != telegram2fa.ErrCooldown {
		t.Fatalf("a cooldown stored as a string must still block, got %q", result.Error)
	}

	if result.NextSendAt == 0 {
		t.Fatal("and must still report when another send is possible")
	}
}

func toInt64(raw any) int64 {
	switch value := raw.(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	}

	return 0
}

func itoa(value int64) string {
	if value == 0 {
		return "0"
	}

	digits := ""

	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}

	return digits
}

func quote(value string) string {
	encoded, _ := json.Marshal(value)

	return string(encoded)
}
