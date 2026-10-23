// Package webhook authenticates Telegram requests and dispatches updates.
package webhook

import (
	"crypto/subtle"
	"net"
	"strconv"
	"strings"
	"time"

	telegram2fa "github.com/getkampe/telegram-2fa/packages/go"
)

// SecretHeader is the header Telegram sends the secret token in.
const SecretHeader = "X-Telegram-Bot-Api-Secret-Token"

// TelegramRanges are Telegram's published webhook source ranges.
var TelegramRanges = []string{"149.154.160.0/20", "91.108.4.0/22"}

// Verifier decides whether a request on the webhook endpoint came from Telegram.
//
// This is the most important check in the library. The webhook URL is public
// and unauthenticated, and what it accepts is an assertion of the form "this
// chat id is asking for a code". Without verification, anyone who learns the
// URL can post an update carrying a chat id and have the bot mint a code for
// whichever account that chat is linked to — and because the code then arrives
// in the real owner's chat, nothing in the application looks wrong.
//
// Telegram supports this directly: register the webhook with a secret_token and
// it sends that token in a header on every request.
type Verifier struct {
	config *telegram2fa.Config
	nets   []*net.IPNet
}

// NewVerifier returns a Verifier for the configuration.
func NewVerifier(config *telegram2fa.Config) *Verifier {
	nets := make([]*net.IPNet, 0, len(TelegramRanges))

	for _, cidr := range TelegramRanges {
		if _, parsed, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, parsed)
		}
	}

	return &Verifier{config: config, nets: nets}
}

// Accepts reports whether the request may be processed.
func (v *Verifier) Accepts(headerValue, remoteIP string) bool {
	if headerValue == "" {
		return false
	}

	// ConstantTimeCompare, so the time taken to reject does not reveal how
	// much of the secret was right. It returns 0 on a length mismatch, which
	// is the behaviour we want.
	if subtle.ConstantTimeCompare([]byte(v.config.WebhookSecret), []byte(headerValue)) != 1 {
		return false
	}

	if v.config.RestrictWebhookIPs && !v.FromTelegram(remoteIP) {
		return false
	}

	return true
}

// FromTelegram reports whether an address falls inside Telegram's ranges.
//
// Only meaningful if remoteIP is the real peer. Behind a load balancer the peer
// is the proxy and the client address comes from a header the caller can set at
// will, which is why this is off by default and the secret token is not.
func (v *Verifier) FromTelegram(remoteIP string) bool {
	if remoteIP == "" {
		return false
	}

	// Tolerate a host:port, which is what http.Request.RemoteAddr carries.
	if host, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = host
	}

	address := net.ParseIP(remoteIP)
	if address == nil {
		return false
	}

	for _, allowed := range v.nets {
		if allowed.Contains(address) {
			return true
		}
	}

	return false
}

// Update is the slice of a Telegram update this library reads.
type Update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		MessageID int64  `json:"message_id"`
		Text      string `json:"text"`
		Chat      *struct {
			ID   any    `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	} `json:"message"`
	CallbackQuery *struct {
		ID      string `json:"id"`
		Data    string `json:"data"`
		Message *struct {
			Chat *struct {
				ID   any    `json:"id"`
				Type string `json:"type"`
			} `json:"chat"`
		} `json:"message"`
	} `json:"callback_query"`
}

// CommandHandler handles an application command such as /balance.
type CommandHandler func(chatID, argument string) error

// Handler turns a verified update into protocol actions.
//
// Framework-free: hand it a parsed update and it does the work. Routing, body
// parsing and the secret-token check belong to the caller.
//
// Commands: /start (with or without a deeplink payload), /code, /status,
// /link, /unlink, /help. Anything else gets a short reply rather than silence,
// because silence from a security bot reads as a broken security bot.
type Handler struct {
	service  *telegram2fa.Service
	config   *telegram2fa.Config
	store    telegram2fa.CodeStore
	telegram telegram2fa.TelegramClient
	messages telegram2fa.Messages
	logger   telegram2fa.Logger
	clock    telegram2fa.Clock

	// AccountLabel produces the label shown in the link confirmation. The
	// default shows nothing identifying; pass something partially masked if
	// you want it, because that message lands in a chat.
	AccountLabel func(userID string) string

	extra map[string]CommandHandler
}

// HandlerOptions are the dependencies a Handler needs.
type HandlerOptions struct {
	Service  *telegram2fa.Service
	Config   *telegram2fa.Config
	Store    telegram2fa.CodeStore
	Telegram telegram2fa.TelegramClient
	Messages telegram2fa.Messages
	Logger   telegram2fa.Logger
	Clock    telegram2fa.Clock
}

// NewHandler returns a Handler.
func NewHandler(opts HandlerOptions) *Handler {
	logger := opts.Logger
	if logger == nil {
		logger = telegram2fa.NullLogger{}
	}

	clock := opts.Clock
	if clock == nil {
		clock = telegram2fa.SystemClock{}
	}

	return &Handler{
		service:  opts.Service,
		config:   opts.Config,
		store:    opts.Store,
		telegram: opts.Telegram,
		messages: opts.Messages,
		logger:   logger,
		clock:    clock,
		extra:    map[string]CommandHandler{},
	}
}

// On registers an application command.
//
// The handler runs only after the update has been verified as coming from
// Telegram, but the argument is still user input: treat it as such.
func (h *Handler) On(command string, handler CommandHandler) *Handler {
	h.extra[strings.ToLower(strings.TrimPrefix(command, "/"))] = handler

	return h
}

// Handle handles one update.
//
// It reports whether the update was acted on. Either way the caller should
// answer 200: a non-2xx makes Telegram retry and queue every later update
// behind this one.
func (h *Handler) Handle(update Update) (bool, error) {
	claim, claimed, err := h.claim(update)
	if err != nil {
		return false, err
	}

	if !claimed {
		return false, nil
	}

	handled, err := h.dispatch(update)

	if err != nil {
		// Release the claim so Telegram's retry is processed rather than
		// discarded as a duplicate. Marking an update done before its work
		// succeeds turns one transient failure into a permanently lost
		// operation.
		if claim != "" {
			//nolint:errcheck // the dispatch error is the one worth reporting
			h.store.Forget(claim)
		}

		return false, err
	}

	// Only now is it really handled, so hold the claim for the full window.
	if claim != "" {
		if err := h.store.Put(claim, "done", h.config.UpdateDedupeTTL); err != nil {
			return handled, err
		}
	}

	return handled, nil
}

func (h *Handler) dispatch(update Update) (bool, error) {
	if update.CallbackQuery != nil {
		return h.handleCallback(update)
	}

	if update.Message == nil || update.Message.Chat == nil {
		return false, nil
	}

	chatID := chatIDOf(update.Message.Chat.ID)
	text := strings.TrimSpace(update.Message.Text)

	if chatID == "" || text == "" {
		return false, nil
	}

	// Private chats only. A bot added to a group would otherwise hand out
	// verification codes in front of every member of it.
	chatType := update.Message.Chat.Type
	if chatType != "" && chatType != "private" {
		return false, nil
	}

	if !strings.HasPrefix(text, "/") {
		// Codes travel application-to-user, never user-to-bot, so free text is
		// not a code to check. Nudging rather than parsing also means a user
		// who pastes a code into the wrong window has not handed it to the bot.
		_, err := h.telegram.SendMessage(chatID, h.messages.UnknownCommand(), nil)

		return false, err
	}

	command, argument := parseCommand(text)

	h.logger.Info("telegram-2fa: command", map[string]any{
		"command":   command,
		"update_id": update.UpdateID,
	})

	switch command {
	case "start":
		return h.start(chatID, argument)
	case "code", "otp", "2fa":
		return h.code(chatID)
	case "status":
		return h.status(chatID)
	case "link":
		return h.link(chatID)
	case "unlink":
		return h.unlinkHint(chatID)
	case "help":
		return h.help(chatID)
	}

	return h.dispatchExtra(command, chatID, argument)
}

func (h *Handler) start(chatID, payload string) (bool, error) {
	if payload == "" {
		return h.help(chatID)
	}

	result, err := h.service.CompleteDeepLink(payload, chatID)
	if err != nil {
		return false, err
	}

	if result.OK && result.Identity != nil {
		label := "your account"
		if h.AccountLabel != nil {
			label = h.AccountLabel(result.Identity.UserID)
		}

		_, err = h.telegram.SendMessage(
			chatID, h.messages.LinkSucceeded(label, h.config.AppName), nil)

		return true, err
	}

	text := h.messages.LinkTokenInvalid()
	if result.Error == telegram2fa.ErrAlreadyLinked {
		text = h.messages.AlreadyLinked()
	}

	_, err = h.telegram.SendMessage(chatID, text, nil)

	return false, err
}

func (h *Handler) link(chatID string) (bool, error) {
	identity, err := h.service.IdentityForChat(chatID)
	if err != nil {
		return false, err
	}

	if identity.IsVerified() {
		_, err = h.telegram.SendMessage(chatID, h.messages.AlreadyLinked(), nil)

		return false, err
	}

	request, err := h.service.StartPasteLink(chatID)
	if err != nil {
		return false, err
	}

	_, err = h.telegram.SendMessage(
		chatID,
		h.messages.LinkInstructions(request.Token, h.config.LinkTTL, h.config.AppName),
		nil,
	)

	return true, err
}

func (h *Handler) code(chatID string) (bool, error) {
	// Pull sends the code itself, so the plaintext never reaches here.
	result, err := h.service.Pull(chatID)
	if err != nil {
		return false, err
	}

	if result.OK {
		return true, nil
	}

	var text string

	switch result.Error {
	case telegram2fa.ErrNotLinked:
		text = h.messages.NotLinked(h.config.AppName)
	case telegram2fa.ErrCooldown:
		text = h.messages.Cooldown(result.RetryAfter(h.clock.Now()))
	default:
		text = h.messages.UnknownCommand()
	}

	_, err = h.telegram.SendMessage(chatID, text, nil)

	return false, err
}

func (h *Handler) status(chatID string) (bool, error) {
	identity, err := h.service.IdentityForChat(chatID)
	if err != nil {
		return false, err
	}

	text := h.messages.NotLinked(h.config.AppName)
	if identity.IsVerified() {
		text = h.messages.Welcome(true, h.config.AppName)
	}

	_, err = h.telegram.SendMessage(chatID, text, nil)

	return true, err
}

// unlinkHint explains where to unlink, and does not unlink.
//
// Whoever holds the phone can already read the codes; letting them also remove
// the factor with no session and no password turns a stolen phone into a
// permanently single-factor account.
func (h *Handler) unlinkHint(chatID string) (bool, error) {
	identity, err := h.service.IdentityForChat(chatID)
	if err != nil {
		return false, err
	}

	if !identity.IsVerified() {
		_, err = h.telegram.SendMessage(chatID, h.messages.NotLinked(h.config.AppName), nil)

		return false, err
	}

	_, err = h.telegram.SendMessage(
		chatID, h.messages.UnlinkInstructions(h.config.AppName), nil)

	return true, err
}

func (h *Handler) help(chatID string) (bool, error) {
	identity, err := h.service.IdentityForChat(chatID)
	if err != nil {
		return false, err
	}

	_, err = h.telegram.SendMessage(
		chatID, h.messages.Welcome(identity.IsVerified(), h.config.AppName), nil)

	return true, err
}

func (h *Handler) dispatchExtra(command, chatID, argument string) (bool, error) {
	handler, ok := h.extra[command]

	if !ok {
		_, err := h.telegram.SendMessage(chatID, h.messages.UnknownCommand(), nil)

		return false, err
	}

	return true, handler(chatID, argument)
}

func (h *Handler) handleCallback(update Update) (bool, error) {
	query := update.CallbackQuery

	if query.ID != "" {
		// Acknowledge first, or the user's client spins for ten seconds.
		//nolint:errcheck // cosmetic; the work below is what matters
		h.telegram.AnswerCallbackQuery(query.ID, "")
	}

	if query.Message == nil || query.Message.Chat == nil {
		return false, nil
	}

	chatID := chatIDOf(query.Message.Chat.ID)
	if chatID == "" {
		return false, nil
	}

	switch query.Data {
	case "code":
		return h.code(chatID)
	case "status":
		return h.status(chatID)
	case "link":
		return h.link(chatID)
	case "help":
		return h.help(chatID)
	}

	return false, nil
}

// claim claims an update, so exactly one attempt processes it.
//
// Telegram retries an update it believes was not delivered, and delivers
// concurrently, so the same update_id can arrive more than once and at the same
// time. Add is the whole mechanism: checking for a marker and then writing one
// is two operations, and two simultaneous deliveries both find nothing and both
// proceed.
func (h *Handler) claim(update Update) (key string, claimed bool, err error) {
	if !h.config.DedupeUpdates || update.UpdateID == 0 {
		return "", true, nil
	}

	key = h.config.Key("update", formatInt(update.UpdateID))

	// A short claim, not the full window: if this process dies mid-handling
	// the claim lapses on its own and a later retry can pick the update up.
	ttl := h.config.UpdateDedupeTTL
	if ttl > 120*time.Second {
		ttl = 120 * time.Second
	}
	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}

	won, err := h.store.Add(key, "claimed", ttl)
	if err != nil {
		return "", false, err
	}

	if !won {
		h.logger.Info("telegram-2fa: duplicate update dropped", map[string]any{
			"update_id": update.UpdateID,
		})

		return "", false, nil
	}

	return key, true, nil
}

func parseCommand(text string) (command, argument string) {
	command = text
	argument = ""

	if index := strings.IndexAny(text, " \t\n"); index >= 0 {
		command = text[:index]
		argument = strings.TrimSpace(text[index+1:])
	}

	command = strings.ToLower(strings.TrimPrefix(command, "/"))

	// In groups Telegram appends the bot name: /code@kampe_bot.
	if index := strings.Index(command, "@"); index >= 0 {
		command = command[:index]
	}

	return command, argument
}

// chatIDOf normalises the chat id, which JSON decodes as a float64 when it
// arrives as a number and as a string when a test or another implementation
// writes it that way.
func chatIDOf(raw any) string {
	switch value := raw.(type) {
	case string:
		return value
	case float64:
		return formatInt(int64(value))
	case int64:
		return formatInt(value)
	case int:
		return formatInt(int64(value))
	}

	return ""
}

func formatInt(value int64) string {
	return strconv.FormatInt(value, 10)
}
