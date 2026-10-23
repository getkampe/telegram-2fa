package telegram2fa

// ChallengeResult is the outcome of asking for a code to be issued and
// delivered.
//
// Note what is absent: the code. Neither challenge direction returns it, which
// is the only reason a result like this can be serialised straight into an HTTP
// response.
type ChallengeResult struct {
	OK    bool      `json:"ok"`
	Error ErrorCode `json:"error,omitempty"`
	// ExpiresAt is when the issued code stops being accepted.
	ExpiresAt int64 `json:"expires_at,omitempty"`
	// NextSendAt is when another code may be requested.
	NextSendAt int64 `json:"next_send_at,omitempty"`
}

// RetryAfter returns the seconds to wait before offering a resend, never
// negative.
func (r ChallengeResult) RetryAfter(now int64) int {
	if r.NextSendAt <= now {
		return 0
	}

	return int(r.NextSendAt - now)
}

func challengeSent(expiresAt, nextSendAt int64) ChallengeResult {
	return ChallengeResult{OK: true, ExpiresAt: expiresAt, NextSendAt: nextSendAt}
}

func challengeFailed(code ErrorCode, nextSendAt int64) ChallengeResult {
	return ChallengeResult{OK: false, Error: code, NextSendAt: nextSendAt}
}

// VerificationResult is the outcome of checking a submitted code.
type VerificationResult struct {
	OK                bool      `json:"ok"`
	Error             ErrorCode `json:"error,omitempty"`
	AttemptsRemaining int       `json:"attempts_remaining,omitempty"`
}

func verificationPassed() VerificationResult {
	return VerificationResult{OK: true}
}

func verificationFailed(code ErrorCode, remaining int) VerificationResult {
	return VerificationResult{OK: false, Error: code, AttemptsRemaining: remaining}
}

// LinkRequest is a pending link, ready to be shown to the user.
//
// This is the one place a secret legitimately leaves the library, because the
// user has to receive it somehow. For the deeplink flow put URL in a button or
// a QR code; for the paste flow show Token in the chat. Either way it does not
// belong in a log line or an audit record.
type LinkRequest struct {
	Token     string
	ExpiresAt int64
	// URL is empty when the bot username is unknown.
	URL string
}

// LinkResult is the outcome of resolving a link token.
type LinkResult struct {
	OK       bool      `json:"ok"`
	Error    ErrorCode `json:"error,omitempty"`
	Identity *Identity `json:"-"`
}

func linkOK(identity *Identity) LinkResult {
	return LinkResult{OK: true, Identity: identity}
}

func linkFailed(code ErrorCode) LinkResult {
	return LinkResult{OK: false, Error: code}
}
