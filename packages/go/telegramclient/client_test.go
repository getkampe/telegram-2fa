package telegramclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
)

// A token shaped like the real thing, so a substring check is meaningful.
const fakeToken = "123456789:AAFakeTokenForTestsOnly_0123456789abc"

// recordingLogger keeps everything written, so a test can assert on all of it.
type recordingLogger struct {
	entries []string
}

func (l *recordingLogger) write(level, message string, context map[string]any) {
	parts := []string{level, message}

	for key, value := range context {
		parts = append(parts, fmt.Sprintf("%s=%v", key, value))
	}

	l.entries = append(l.entries, strings.Join(parts, " "))
}

func (l *recordingLogger) Info(message string, context map[string]any) {
	l.write("info", message, context)
}

func (l *recordingLogger) Warn(message string, context map[string]any) {
	l.write("warn", message, context)
}

func (l *recordingLogger) Error(message string, context map[string]any) {
	l.write("error", message, context)
}

func (l *recordingLogger) everything() string {
	return strings.Join(l.entries, "\n")
}

// failingTransport fails the way a real one does: with a *url.Error carrying
// the request URL, which is what http.Client.Do wraps a transport error in.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp 149.154.167.220:443: connectex: connection refused")
}

func clientWith(transport http.RoundTripper, logger telegram2fa.Logger) *Client {
	return New(Options{
		BotToken:   fakeToken,
		HTTPClient: &http.Client{Transport: transport},
		Logger:     logger,
	})
}

// The bot token travels in the request URL, because that is the API Telegram
// exposes. http.Client.Do wraps a transport failure in a *url.Error whose
// Error() embeds that URL, so building a log line out of it writes the token
// into the log - and a token in a log file is a bot that anyone who can read
// the file can impersonate.
func TestATransportFailureDoesNotLogTheBotToken(t *testing.T) {
	logger := &recordingLogger{}
	client := clientWith(failingTransport{}, logger)

	sent, err := client.SendMessage("555000111", "hello", nil)
	if sent || err != nil {
		t.Fatalf("expected a reported failure, got sent=%v err=%v", sent, err)
	}

	if len(logger.entries) == 0 {
		t.Fatal("the failure must be logged, or this test proves nothing")
	}

	logged := logger.everything()

	if strings.Contains(logged, fakeToken) {
		t.Errorf("the bot token reached the log: %s", logged)
	}

	// The distinctive half on its own, in case only part of it survives some
	// future reformatting.
	if strings.Contains(logged, "123456789:") {
		t.Errorf("part of the bot token reached the log: %s", logged)
	}

	if !strings.Contains(logged, redacted) && strings.Contains(logged, "api.telegram.org/bot") {
		t.Errorf("a request URL reached the log unredacted: %s", logged)
	}
}

// The error travels to the caller, who will log it too.
func TestATransportFailureDoesNotCarryTheBotTokenToTheCaller(t *testing.T) {
	client := clientWith(failingTransport{}, telegram2fa.NullLogger{})

	_, err := client.GetMe()
	if err == nil {
		t.Fatal("expected an error")
	}

	if strings.Contains(err.Error(), fakeToken) {
		t.Errorf("the bot token is in the returned error: %s", err.Error())
	}
}

// Belt and braces: an error that carries the token without being a *url.Error
// is still redacted, because unwrapping only helps for the shapes we predicted.
func TestAnUnexpectedErrorShapeIsStillRedacted(t *testing.T) {
	client := clientWith(nil, telegram2fa.NullLogger{})

	text := client.reason(fmt.Errorf("something odd happened to %s%s/sendMessage", base, fakeToken))

	if strings.Contains(text, fakeToken) {
		t.Errorf("the token survived redaction: %s", text)
	}

	if !strings.Contains(text, redacted) {
		t.Errorf("expected a redaction marker, got: %s", text)
	}
}

func TestAnAcceptedSendReportsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"result":{"message_id":1}}`)
	}))
	defer server.Close()

	client := clientWith(rewriteTo(server.URL), telegram2fa.NullLogger{})

	sent, err := client.SendMessage("555000111", "hello", nil)
	if !sent || err != nil {
		t.Fatalf("expected success, got sent=%v err=%v", sent, err)
	}
}

// A 2xx is not an acceptance: the Bot API answers 200 with ok:false for a
// blocked bot or a chat that no longer exists.
func TestATwoHundredCarryingOkFalseIsAFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`)
	}))
	defer server.Close()

	logger := &recordingLogger{}
	client := clientWith(rewriteTo(server.URL), logger)

	sent, err := client.SendMessage("555000111", "hello", nil)
	if sent || err != nil {
		t.Fatalf("expected a reported failure, got sent=%v err=%v", sent, err)
	}

	// This port surfaces Telegram's own description, on the grounds that it
	// never echoes the message body back. The C# port makes the stricter
	// choice and logs only the numeric code; both are defensible, and what
	// matters here is that the refusal is diagnosable rather than silent.
	if !strings.Contains(logger.everything(), "Forbidden") {
		t.Errorf("the refusal must be diagnosable: %s", logger.everything())
	}
}

func TestANonJSONTwoHundredIsAFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>captive portal</html>")
	}))
	defer server.Close()

	client := clientWith(rewriteTo(server.URL), telegram2fa.NullLogger{})

	if sent, _ := client.SendMessage("555000111", "hello", nil); sent {
		t.Error("a 200 carrying HTML is not Telegram saying yes")
	}
}

// rewriteTo points requests at a test server while leaving the path - and so
// the token in it - exactly as the client built it.
func rewriteTo(target string) http.RoundTripper {
	return &rewritingTransport{target: target}
}

type rewritingTransport struct {
	target string
}

func (t *rewritingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(t.target, "http://")

	return http.DefaultTransport.RoundTrip(clone)
}
