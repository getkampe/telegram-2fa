package telegram2fa

import "fmt"

// ErrorCode is the protocol error vocabulary of SPEC.md section 10.
//
// The string values are the wire form, shared with every other implementation,
// so a client written against them works against any of them. Do not change
// the values.
type ErrorCode string

const (
	// ErrNotLinked means the account has no verified Telegram link.
	ErrNotLinked ErrorCode = "not_linked"
	// ErrAlreadyLinked means the account, or the chat, is already linked.
	ErrAlreadyLinked ErrorCode = "already_linked"
	// ErrCooldown means a code was sent too recently.
	ErrCooldown ErrorCode = "cooldown"
	// ErrSendFailed means Telegram did not accept the message.
	ErrSendFailed ErrorCode = "send_failed"
	// ErrInvalid means the submitted code does not match.
	ErrInvalid ErrorCode = "invalid"
	// ErrExpired means there is no live code: never issued, aged out, or used.
	ErrExpired ErrorCode = "expired"
	// ErrTooManyAttempts means the attempt budget for this code is exhausted.
	ErrTooManyAttempts ErrorCode = "too_many_attempts"
	// ErrInvalidToken means a link token is unknown, expired or already used.
	ErrInvalidToken ErrorCode = "invalid_token"
	// ErrWebhookUnauthorized means the webhook secret was missing or wrong.
	ErrWebhookUnauthorized ErrorCode = "webhook_unauthorized"
)

// Message returns text safe to show an end user.
//
// Deliberately vague about which of "never issued", "expired" and "already
// used" applies, because distinguishing them tells an attacker holding a
// session whether a challenge is in flight.
func (c ErrorCode) Message() string {
	switch c {
	case ErrNotLinked:
		return "No Telegram account is linked to this profile."
	case ErrAlreadyLinked:
		return "This Telegram account is already linked."
	case ErrCooldown:
		return "A code was just sent. Please wait before requesting another."
	case ErrSendFailed:
		return "The code could not be delivered. Please try again or use another method."
	case ErrInvalid:
		return "That code is not valid."
	case ErrExpired:
		return "That code is no longer valid. Request a new one."
	case ErrTooManyAttempts:
		return "Too many incorrect attempts. Request a new code."
	case ErrInvalidToken:
		return "This link has expired or has already been used."
	case ErrWebhookUnauthorized:
		return "Unauthorized."
	}

	return "Verification failed."
}

// ConfigError reports a configuration that cannot produce a secure
// installation. Returned when the config is built, never mid-request.
type ConfigError struct {
	Field  string
	Reason string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("telegram2fa: %s: %s", e.Field, e.Reason)
}

// RequestError reports that Telegram refused a request or could not be reached.
type RequestError struct {
	Method string
	Reason string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("telegram2fa: %s failed: %s", e.Method, e.Reason)
}
