// Package telegram2fa implements Telegram as a second authentication factor.
//
// The whole protocol with no framework underneath it: linking (three flows),
// challenge (two directions), verification, unlinking. Everything it touches
// arrives through an interface, so the same code runs on Redis and Postgres or
// on maps in a test.
//
// See SPEC.md at the root of the repository for the normative protocol, which
// the PHP, Node and Python packages implement too — all four interoperate
// against one bot and one store.
package telegram2fa

import (
	"errors"
	"time"
)

// AnyGeneration is the expectation meaning "whatever is there now", for
// recovery paths where the caller has already proved identity by other means
// and must not be blocked by a concurrent change.
const AnyGeneration = "\x00any"

// Identity is an account's Telegram enrollment, as the identity store holds it.
//
// This represents the row rather than only the linked state, so an account that
// has been unlinked still has an Identity — carrying no chat, but carrying the
// generation. That is deliberate: revocation has to outlive the binding it
// revokes, or a token minted before an unlink would come back to life when the
// user links again.
type Identity struct {
	UserID string
	// ChatID is empty when the account is not currently linked.
	ChatID string
	// LinkedAt is zero when the link is not proven.
	LinkedAt int64
	// Generation is empty only for a row that has never been enrolled.
	//
	// Anything holding authority over an enrollment records this value and is
	// refused once it differs.
	Generation string
}

// IsVerified reports whether this is a proven second factor.
//
// A row carrying a chat id with no verification timestamp is a link that was
// started and never completed. Treating it as linked would let anyone who can
// write a chat id into the row satisfy a challenge.
func (i *Identity) IsVerified() bool {
	return i != nil && i.ChatID != "" && i.LinkedAt != 0
}

// CodeStore is short-lived key/value storage with a TTL.
//
// Redis, Memcached, a table with an expires_at column — anything with expiry.
// It holds code hashes, never plaintext codes.
//
// Take and Add must be atomic. They are not a convenience: a verification built
// from get-check-delete is a time-of-check-to-time-of-use race, and two
// requests arriving together both read the live record, both match it, and both
// succeed — so a single-use code is used twice, and the attempt counter loses
// increments to the same lost-update race. Single use and the attempt budget
// are the two things standing between a six-digit code and an attacker, so they
// cannot rest on a sequence the store is free to interleave.
//
// A note on types: a store need not hand back exactly what it was given. The
// PHP package's Redis adapter returns a bare numeric as a numeric string,
// because Laravel leaves such values unserialised so INCR still works on them.
// Hence Record and CooldownOf, which coerce rather than type-assert.
type CodeStore interface {
	Get(key string) (any, error)
	Put(key string, value any, ttl time.Duration) error
	Forget(key string) error

	// Take atomically reads a value and removes it. It returns nil when the
	// key is absent. Exactly one caller may receive a given value: Redis has
	// GETDEL or EVAL, a SQL store has DELETE ... RETURNING.
	Take(key string) (any, error)

	// Add atomically writes only if the key is absent, reporting whether it
	// did. The boolean is the point: it makes the write a reservation exactly
	// one caller can win, which is how the cooldown and the webhook's
	// idempotency claim avoid check-then-write races.
	Add(key string, value any, ttl time.Duration) (bool, error)
}

// IdentityStore is durable storage of the enrollment.
//
// Two rules the implementation, not the caller, has to guarantee:
//
//  1. Chat uniqueness at the storage layer — a unique index, not only an
//     application check, because two concurrent links both pass a check and
//     only one can pass an index.
//  2. Transitions are conditional. Every change goes through Transition, which
//     compares the stored generation and writes in one operation.
//     Read-then-write cannot express this: a recovery landing between a
//     caller's validation and its write would be silently overwritten, which is
//     how a replacement token outlives the enrollment it proved.
type IdentityStore interface {
	// FindByUserID returns the enrollment, or nil when the account has no row.
	// The generation must be returned even when no chat is linked.
	FindByUserID(userID string) (*Identity, error)

	// FindByChatID must never match an account whose chat id is empty.
	FindByChatID(chatID string) (*Identity, error)

	// Transition compare-and-sets the enrollment.
	//
	// expected is the generation the caller believes is current; the empty
	// string means "none recorded yet"; AnyGeneration skips the check.
	//
	// It returns nil, nil when the expectation did not hold — in which case the
	// stored row must be left exactly as it was — and ErrChatAlreadyLinked when
	// the chat belongs to another account.
	Transition(userID, chatID, expected, next string) (*Identity, error)
}

// TelegramClient is the slice of the Telegram Bot API this library needs.
type TelegramClient interface {
	SendMessage(chatID, text string, inlineKeyboard [][]InlineButton) (bool, error)
	AnswerCallbackQuery(callbackQueryID, text string) (bool, error)
	GetMe() (map[string]any, error)
	SetWebhook(url, secretToken string, allowedUpdates []string) (bool, error)
	DeleteWebhook() (bool, error)
}

// InlineButton is one button in an inline keyboard.
type InlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// Messages is every piece of text the bot sends.
//
// All strings are sent with parse_mode HTML, so an implementation that
// interpolates user-supplied text must escape it — see EscapeHTML.
type Messages interface {
	Code(code string, ttl time.Duration) string
	LinkInstructions(code string, ttl time.Duration, appName string) string
	LinkSucceeded(accountLabel, appName string) string
	LinkTokenInvalid() string
	AlreadyLinked() string
	NotLinked(appName string) string
	Cooldown(secondsRemaining int) string
	UnlinkInstructions(appName string) string
	Unlinked(appName string) string
	Welcome(isLinked bool, appName string) string
	UnknownCommand() string
}

// Clock is a wall clock, injectable so expiry and cooldown are testable without
// sleeping.
type Clock interface {
	Now() int64
}

// SystemClock reads the real time.
type SystemClock struct{}

func (SystemClock) Now() int64 { return time.Now().Unix() }

// Logger is a narrow logging surface.
//
// Nothing this library passes to it contains a code, a link token or a raw
// update body — and the update body is the important one, because for this bot
// the update body is the code.
type Logger interface {
	Info(message string, fields map[string]any)
	Warn(message string, fields map[string]any)
	Error(message string, fields map[string]any)
}

// NullLogger discards everything. The default, so the library never writes to a
// log the host application did not hand it.
type NullLogger struct{}

func (NullLogger) Info(string, map[string]any)  {}
func (NullLogger) Warn(string, map[string]any)  {}
func (NullLogger) Error(string, map[string]any) {}

// ErrChatAlreadyLinked is returned by an identity store when a chat already
// belongs to a different account.
//
// Stores return this rather than reassigning: one Telegram account acting as
// the second factor for several accounts means one compromised Telegram account
// compromises all of them.
var ErrChatAlreadyLinked = errors.New("telegram2fa: that chat is already the second factor for another account")
