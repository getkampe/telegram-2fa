// Package telegramclient talks to the Telegram Bot API over net/http.
package telegramclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
)

const base = "https://api.telegram.org/bot"

// Client is the default Telegram client. Substitute your own implementation of
// telegram2fa.TelegramClient to route through a queue or an existing bot
// library.
type Client struct {
	botToken  string
	http      *http.Client
	logger    telegram2fa.Logger
	parseMode string
}

// Options configure a Client.
type Options struct {
	BotToken string
	// Timeout defaults to ten seconds.
	Timeout time.Duration
	Logger  telegram2fa.Logger
	// HTTPClient lets a caller supply its own transport. TLS verification must
	// stay on: a bot token travelling over an unverified connection is a bot
	// token handed to whoever is in the middle of it.
	HTTPClient *http.Client
	// ParseMode defaults to HTML.
	ParseMode string
}

// New returns a Client.
func New(opts Options) *Client {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}

	logger := opts.Logger
	if logger == nil {
		logger = telegram2fa.NullLogger{}
	}

	parseMode := opts.ParseMode
	if parseMode == "" {
		parseMode = "HTML"
	}

	return &Client{
		botToken:  opts.BotToken,
		http:      httpClient,
		logger:    logger,
		parseMode: parseMode,
	}
}

// SendMessage sends a message to a chat.
func (c *Client) SendMessage(
	chatID, text string, inlineKeyboard [][]telegram2fa.InlineButton,
) (bool, error) {
	payload := map[string]any{
		"chat_id":                  chatID,
		"text":                     text,
		"parse_mode":               c.parseMode,
		"disable_web_page_preview": true,
	}

	if inlineKeyboard != nil {
		payload["reply_markup"] = map[string]any{"inline_keyboard": inlineKeyboard}
	}

	if _, err := c.call("sendMessage", payload); err != nil {
		// Delivery is fallible and the caller has a fallback path, so this is
		// reported rather than returned as a hard failure. The message body is
		// never logged: for a challenge, the body is the code.
		c.logger.Error("telegram-2fa: sendMessage failed", map[string]any{
			"reason": err.Error(),
		})

		return false, nil
	}

	return true, nil
}

// AnswerCallbackQuery acknowledges a callback so the client stops spinning.
func (c *Client) AnswerCallbackQuery(callbackQueryID, text string) (bool, error) {
	payload := map[string]any{"callback_query_id": callbackQueryID}

	if text != "" {
		payload["text"] = text
	}

	if _, err := c.call("answerCallbackQuery", payload); err != nil {
		return false, nil
	}

	return true, nil
}

// GetMe returns the bot's identity.
func (c *Client) GetMe() (map[string]any, error) {
	result, err := c.call("getMe", map[string]any{})
	if err != nil {
		return nil, err
	}

	if identity, ok := result.(map[string]any); ok {
		return identity, nil
	}

	return map[string]any{}, nil
}

// SetWebhook registers the webhook URL with its secret token.
func (c *Client) SetWebhook(url, secretToken string, allowedUpdates []string) (bool, error) {
	if !strings.HasPrefix(url, "https://") {
		return false, &telegram2fa.RequestError{
			Method: "setWebhook",
			Reason: "Telegram will only deliver webhooks to an https URL with a valid certificate",
		}
	}

	if allowedUpdates == nil {
		allowedUpdates = []string{"message", "callback_query"}
	}

	_, err := c.call("setWebhook", map[string]any{
		"url":             url,
		"secret_token":    secretToken,
		"allowed_updates": allowedUpdates,
		// Telegram queues updates while a webhook is unset or failing. On a
		// first deploy that queue can hold stale /code requests, so it is
		// dropped rather than replayed into a live 2FA flow.
		"drop_pending_updates": true,
	})

	return err == nil, err
}

// DeleteWebhook removes the registered webhook.
func (c *Client) DeleteWebhook() (bool, error) {
	_, err := c.call("deleteWebhook", map[string]any{"drop_pending_updates": true})

	return err == nil, err
}

func (c *Client) call(method string, payload map[string]any) (any, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, &telegram2fa.RequestError{Method: method, Reason: err.Error()}
	}

	request, err := http.NewRequest(http.MethodPost, base+c.botToken+"/"+method, bytes.NewReader(body))
	if err != nil {
		return nil, &telegram2fa.RequestError{Method: method, Reason: err.Error()}
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := c.http.Do(request)
	if err != nil {
		return nil, &telegram2fa.RequestError{
			Method: method,
			Reason: "Telegram could not be reached: " + err.Error(),
		}
	}

	defer response.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, &telegram2fa.RequestError{Method: method, Reason: err.Error()}
	}

	var decoded struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      any    `json:"result"`
	}

	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, &telegram2fa.RequestError{
			Method: method,
			Reason: fmt.Sprintf("non-JSON response with status %d", response.StatusCode),
		}
	}

	if !decoded.OK {
		description := decoded.Description
		if description == "" {
			description = "no description"
		}

		// Telegram's own description does not echo the message body back, so
		// it is safe to surface.
		return nil, &telegram2fa.RequestError{
			Method: method,
			Reason: fmt.Sprintf("status %d: %s", response.StatusCode, description),
		}
	}

	return decoded.Result, nil
}
