package telegram2fa

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Purposes name the step a code authorises.
const (
	// PurposeLogin is the default, for an ordinary sign-in.
	PurposeLogin = "login"
	// PurposeOnDemand is the purpose of a code the user fetched with /code.
	//
	// Such a code carries no knowledge of what it is about to authorise, so it
	// satisfies any requested purpose. That is sound because the user asked
	// for it deliberately — nothing the application did caused it to exist.
	PurposeOnDemand = "on_demand"
	// PurposeReplace proves the current factor before rebinding to a new chat.
	PurposeReplace = "replace"
	// PurposeUnlink proves the current factor before removing it.
	PurposeUnlink = "unlink"
)

// Service implements the protocol.
type Service struct {
	config     *Config
	store      CodeStore
	identities IdentityStore
	telegram   TelegramClient
	messages   Messages
	clock      Clock
	logger     Logger
	codes      CodeGenerator
	hasher     *CodeHasher
}

// Options are the dependencies a Service needs.
type Options struct {
	Config     *Config
	Store      CodeStore
	Identities IdentityStore
	Telegram   TelegramClient
	Messages   Messages
	// Clock defaults to SystemClock.
	Clock Clock
	// Logger defaults to NullLogger.
	Logger Logger
}

// New returns a Service.
func New(opts Options) (*Service, error) {
	if opts.Config == nil {
		return nil, &ConfigError{Field: "Config", Reason: "required"}
	}
	if opts.Store == nil {
		return nil, &ConfigError{Field: "Store", Reason: "required"}
	}
	if opts.Identities == nil {
		return nil, &ConfigError{Field: "Identities", Reason: "required"}
	}
	if opts.Telegram == nil {
		return nil, &ConfigError{Field: "Telegram", Reason: "required"}
	}
	if opts.Messages == nil {
		return nil, &ConfigError{Field: "Messages", Reason: "required"}
	}

	hasher, err := NewCodeHasher(opts.Config.HashAlgorithm, opts.Config.HashPepper)
	if err != nil {
		return nil, err
	}

	clock := opts.Clock
	if clock == nil {
		clock = SystemClock{}
	}

	logger := opts.Logger
	if logger == nil {
		logger = NullLogger{}
	}

	return &Service{
		config:     opts.Config,
		store:      opts.Store,
		identities: opts.Identities,
		telegram:   opts.Telegram,
		messages:   opts.Messages,
		clock:      clock,
		logger:     logger,
		hasher:     hasher,
	}, nil
}

// Config returns the validated configuration.
func (s *Service) Config() *Config { return s.config }

// ---------------------------------------------------------------- identity

// IsLinked reports whether this account has a proven Telegram second factor.
func (s *Service) IsLinked(userID string) (bool, error) {
	identity, err := s.identities.FindByUserID(userID)
	if err != nil {
		return false, err
	}

	return identity.IsVerified(), nil
}

// Identity returns the enrollment for an account, or nil.
func (s *Service) Identity(userID string) (*Identity, error) {
	return s.identities.FindByUserID(userID)
}

// IdentityForChat returns the enrollment behind a chat, for the webhook side.
func (s *Service) IdentityForChat(chatID string) (*Identity, error) {
	return s.identities.FindByChatID(chatID)
}

// ----------------------------------------------------------------- linking

// StartDeepLink mints a nonce bound to this account.
//
// Hand the returned URL to the user as a button, or as a QR code when they are
// on a desktop with Telegram on their phone. The token is bound to the account
// before it ever reaches Telegram, which is what makes this flow preferable to
// the paste flow: there is no window in which a token is valid for whoever
// happens to present it.
//
// Minting is harmless for an already-linked account, so this does not check;
// the check happens in CompleteDeepLink.
func (s *Service) StartDeepLink(userID string) (*LinkRequest, error) {
	token, err := s.codes.DeepLinkToken()
	if err != nil {
		return nil, err
	}

	expiresAt := s.clock.Now() + int64(s.config.LinkTTL.Seconds())

	err = s.store.Put(
		s.config.Key("link", s.hasher.Hash(token, "")),
		map[string]any{"user_id": userID, "expires_at": expiresAt},
		s.config.LinkTTL,
	)
	if err != nil {
		return nil, err
	}

	s.logger.Info("telegram-2fa: deeplink issued", map[string]any{"user_id": userID})

	return &LinkRequest{
		Token:     token,
		ExpiresAt: expiresAt,
		URL:       s.config.DeepLinkURL(token),
	}, nil
}

// CompleteDeepLink finishes the flow from a /start payload in a webhook update.
func (s *Service) CompleteDeepLink(token, chatID string) (LinkResult, error) {
	// Single use, and taken atomically: a token read now and deleted later can
	// be resolved twice by two concurrent /start messages, and a token that
	// survives a failed attempt can be retried by anyone who saw it — and it
	// travelled through a chat, so others may have.
	raw, err := s.store.Take(s.config.Key("link", s.hasher.Hash(token, "")))
	if err != nil {
		return LinkResult{}, err
	}

	record := asRecord(raw)

	userID := recordString(record, "user_id")
	if record == nil || userID == "" {
		s.logger.Warn("telegram-2fa: deeplink token not resolvable", map[string]any{
			"chat_id": chatID,
		})

		return linkFailed(ErrInvalidToken), nil
	}

	if recordInt(record, "expires_at") < s.clock.Now() {
		return linkFailed(ErrInvalidToken), nil
	}

	replace := recordBool(record, "replace")
	proven := recordString(record, "generation")

	// A replacement token carries authority over an existing enrollment, so it
	// is only valid against the one whose possession was proved. If that
	// enrollment has since changed — recovered through support, unlinked, or
	// already replaced — the proof no longer refers to anything.
	if replace {
		current, err := s.generationIsCurrent(userID, proven)
		if err != nil {
			return LinkResult{}, err
		}

		if !current {
			s.logger.Warn("telegram-2fa: stale replacement token rejected", map[string]any{
				"user_id": userID,
			})

			return linkFailed(ErrInvalidToken), nil
		}
	}

	return s.bind(userID, chatID, replace, proven)
}

// StartPasteLink mints a code bound to this chat, from the bot side.
func (s *Service) StartPasteLink(chatID string) (*LinkRequest, error) {
	code, err := s.codes.LinkCode(s.config.LinkCodeLength)
	if err != nil {
		return nil, err
	}

	expiresAt := s.clock.Now() + int64(s.config.LinkTTL.Seconds())

	err = s.store.Put(
		s.config.Key("link", s.hasher.Hash(code, "")),
		map[string]any{"chat_id": chatID, "expires_at": expiresAt},
		s.config.LinkTTL,
	)
	if err != nil {
		return nil, err
	}

	s.logger.Info("telegram-2fa: paste link code issued", nil)

	return &LinkRequest{Token: code, ExpiresAt: expiresAt}, nil
}

// CompletePasteLink finishes the paste flow from an authenticated page.
//
// Two things this cannot check are the caller's: that userID comes from the
// session rather than the request body, and that the endpoint is rate-limited.
// Without the rate limit the attempt budget on this flow is unbounded, and link
// codes share one namespace across all users.
func (s *Service) CompletePasteLink(userID, code string) (LinkResult, error) {
	normalised := strings.ToUpper(strings.TrimSpace(code))

	raw, err := s.store.Take(s.config.Key("link", s.hasher.Hash(normalised, "")))
	if err != nil {
		return LinkResult{}, err
	}

	record := asRecord(raw)
	chatID := recordString(record, "chat_id")

	if record == nil || chatID == "" {
		s.logger.Warn("telegram-2fa: paste code not resolvable", map[string]any{
			"user_id": userID,
		})

		return linkFailed(ErrInvalidToken), nil
	}

	if recordInt(record, "expires_at") < s.clock.Now() {
		return linkFailed(ErrInvalidToken), nil
	}

	return s.bind(userID, chatID, false, "")
}

// StartChatReplacement begins moving the factor to a different Telegram account.
//
// Linking never silently moves a verified enrollment, because a flow that did
// would let anyone holding a session attach their own chat. So replacement is
// explicit and costs a code from the chat being replaced: prove the current
// factor here, then resolve the returned token from the new chat.
//
// A user who has lost the old chat entirely cannot do this, and belongs in
// UnlinkAfterExternalProof instead.
//
// On a failed proof it returns a nil request and the VerificationResult that
// stopped it.
func (s *Service) StartChatReplacement(userID, code string) (*LinkRequest, VerificationResult, error) {
	identity, err := s.identities.FindByUserID(userID)
	if err != nil {
		return nil, VerificationResult{}, err
	}

	if !identity.IsVerified() {
		return nil, verificationFailed(ErrNotLinked, 0), nil
	}

	// Captured *before* verifying, because this is the enrollment the user is
	// about to prove possession of. It is what the token must record.
	proven := identity.Generation

	proof, err := s.Verify(userID, code, PurposeReplace)
	if err != nil {
		return nil, VerificationResult{}, err
	}

	if !proof.OK {
		return nil, proof, nil
	}

	if proven == "" {
		// A row enrolled before the generation existed. Assign one,
		// conditional on it still being absent — which doubles as the check
		// below: if anything changed the enrollment while the code was being
		// verified, the generation is no longer empty and this declines.
		next, err := s.codes.EnrollmentGeneration()
		if err != nil {
			return nil, VerificationResult{}, err
		}

		assigned, err := s.identities.Transition(userID, identity.ChatID, "", next)
		if err != nil {
			return nil, VerificationResult{}, err
		}

		if !assigned.IsVerified() || assigned.Generation == "" {
			return nil, verificationFailed(ErrExpired, 0), nil
		}

		request, err := s.mintReplacementToken(userID, assigned.Generation)

		return request, verificationPassed(), err
	}

	// Confirm the enrollment did not move while the code was being verified,
	// and reject if it did. What must never happen is adopting the generation
	// read *after* verification: a recovery landing in that window would have
	// its own new generation, and recording that would hand this token
	// authority over an enrollment the user never proved — the recovered one.
	after, err := s.identities.FindByUserID(userID)
	if err != nil {
		return nil, VerificationResult{}, err
	}

	if !after.IsVerified() || !hmac.Equal([]byte(after.Generation), []byte(proven)) {
		s.logger.Warn("telegram-2fa: enrollment changed during replacement authorisation",
			map[string]any{"user_id": userID})

		return nil, verificationFailed(ErrExpired, 0), nil
	}

	request, err := s.mintReplacementToken(userID, proven)

	return request, verificationPassed(), err
}

// mintReplacementToken stores a token against exactly one generation.
//
// Separate so there is a single place the generation is written, and so no
// caller can pass one it read later than the proof.
func (s *Service) mintReplacementToken(userID, provenGeneration string) (*LinkRequest, error) {
	token, err := s.codes.DeepLinkToken()
	if err != nil {
		return nil, err
	}

	expiresAt := s.clock.Now() + int64(s.config.LinkTTL.Seconds())

	// The replace mark lives on the stored token, not on the call that
	// resolves it. Taking it from the resolution side would make the proof
	// skippable by presenting an ordinary token.
	err = s.store.Put(
		s.config.Key("link", s.hasher.Hash(token, "")),
		map[string]any{
			"user_id":    userID,
			"expires_at": expiresAt,
			"replace":    true,
			"generation": provenGeneration,
		},
		s.config.LinkTTL,
	)
	if err != nil {
		return nil, err
	}

	s.logger.Info("telegram-2fa: chat replacement authorised", map[string]any{
		"user_id": userID,
	})

	return &LinkRequest{
		Token:     token,
		ExpiresAt: expiresAt,
		URL:       s.config.DeepLinkURL(token),
	}, nil
}

// bind records the enrollment, as one conditional transition.
//
// Everything here hangs on handing the store an expectation rather than reading
// state and then writing it. The validation above happens a moment earlier, and
// a recovery or a competing link can land in between; passing the generation we
// believed was current means such a write fails instead of overwriting whatever
// replaced it.
func (s *Service) bind(userID, chatID string, replace bool, provenGeneration string) (LinkResult, error) {
	existing, err := s.identities.FindByUserID(userID)
	if err != nil {
		return LinkResult{}, err
	}

	var replacing *Identity

	if existing.IsVerified() {
		// Re-presenting the same chat is a double submit, not a conflict.
		if existing.ChatID == chatID {
			return linkOK(existing), nil
		}

		if !replace {
			return linkFailed(ErrAlreadyLinked), nil
		}

		replacing = existing
	}

	expected := provenGeneration

	if !replace {
		expected = ""

		if existing != nil {
			expected = existing.Generation
		}
	}

	holder, err := s.identities.FindByChatID(chatID)
	if err != nil {
		return LinkResult{}, err
	}

	if holder != nil && holder.UserID != userID {
		s.logger.Warn("telegram-2fa: chat already linked to another account", map[string]any{
			"user_id": userID,
		})

		return linkFailed(ErrAlreadyLinked), nil
	}

	next, err := s.codes.EnrollmentGeneration()
	if err != nil {
		return LinkResult{}, err
	}

	// One write. It either moves the enrollment or changes nothing, so a
	// replacement onto an unavailable chat — or one overtaken by a recovery —
	// leaves the existing enrollment exactly as it was, rather than stripping
	// the account of its second factor as a side effect of a failed request.
	identity, err := s.identities.Transition(userID, chatID, expected, next)

	if errors.Is(err, ErrChatAlreadyLinked) {
		// The store's uniqueness constraint caught what the check above raced
		// past. The loser's existing enrollment is untouched.
		return linkFailed(ErrAlreadyLinked), nil
	}

	if err != nil {
		return LinkResult{}, err
	}

	if identity == nil {
		s.logger.Warn("telegram-2fa: enrollment changed during link", map[string]any{
			"user_id": userID,
			"replace": replace,
		})

		if replace {
			return linkFailed(ErrInvalidToken), nil
		}

		return linkFailed(ErrAlreadyLinked), nil
	}

	if replacing != nil {
		// Any code in flight was delivered to the chat that is no longer the
		// factor. The generation has already changed, so such a code is
		// unusable even if this cleanup loses a race; this stops it lingering.
		if err := s.clearPending(userID); err != nil {
			return LinkResult{}, err
		}

		// Afterwards, so a failed replacement never announces one.
		if replacing.ChatID != "" {
			//nolint:errcheck // best effort, and the link has already succeeded
			s.telegram.SendMessage(replacing.ChatID, s.messages.Unlinked(s.config.AppName), nil)
		}

		s.logger.Info("telegram-2fa: factor replaced", map[string]any{"user_id": userID})

		return linkOK(identity), nil
	}

	s.logger.Info("telegram-2fa: linked", map[string]any{"user_id": userID})

	return linkOK(identity), nil
}

// --------------------------------------------------------------- challenge

// Push issues a code and sends it to the linked chat.
//
// The code is not in the return value. It is generated, hashed into the store,
// handed to Telegram, and dropped.
func (s *Service) Push(userID, purpose string) (ChallengeResult, error) {
	if purpose == "" {
		purpose = PurposeLogin
	}

	identity, err := s.identities.FindByUserID(userID)
	if err != nil {
		return ChallengeResult{}, err
	}

	if !identity.IsVerified() {
		return challengeFailed(ErrNotLinked, 0), nil
	}

	blocked, err := s.reserveSend(userID)
	if err != nil {
		return ChallengeResult{}, err
	}

	if blocked != 0 {
		return challengeFailed(ErrCooldown, blocked), nil
	}

	code, challengeID, err := s.issue(userID, purpose, identity.Generation)
	if err != nil {
		return ChallengeResult{}, err
	}

	sent, err := s.telegram.SendMessage(
		identity.ChatID,
		s.messages.Code(code, s.config.CodeTTL),
		nil,
	)

	if err != nil || !sent {
		// Drop the code rather than leaving one live that the user never
		// received. Conditionally, so a slow failure cannot delete a code
		// issued after it.
		if discardErr := s.discardChallenge(userID, challengeID); discardErr != nil {
			return ChallengeResult{}, discardErr
		}

		s.logger.Error("telegram-2fa: delivery failed", map[string]any{"user_id": userID})

		return challengeFailed(ErrSendFailed, 0), nil
	}

	s.logger.Info("telegram-2fa: code sent", map[string]any{
		"user_id": userID,
		"purpose": purpose,
	})

	now := s.clock.Now()

	return challengeSent(
		now+int64(s.config.CodeTTL.Seconds()),
		now+int64(s.config.Cooldown.Seconds()),
	), nil
}

// Pull issues a code because the user asked the bot for one.
//
// Writes the same store key as Push, so one verification call accepts a code
// from either direction — see the single-key rule in SPEC.md section 4.
func (s *Service) Pull(chatID string) (ChallengeResult, error) {
	identity, err := s.identities.FindByChatID(chatID)
	if err != nil {
		return ChallengeResult{}, err
	}

	if !identity.IsVerified() {
		return challengeFailed(ErrNotLinked, 0), nil
	}

	blocked, err := s.reserveSend(identity.UserID)
	if err != nil {
		return ChallengeResult{}, err
	}

	if blocked != 0 {
		return challengeFailed(ErrCooldown, blocked), nil
	}

	code, challengeID, err := s.issue(identity.UserID, PurposeOnDemand, identity.Generation)
	if err != nil {
		return ChallengeResult{}, err
	}

	sent, err := s.telegram.SendMessage(chatID, s.messages.Code(code, s.config.CodeTTL), nil)

	if err != nil || !sent {
		if discardErr := s.discardChallenge(identity.UserID, challengeID); discardErr != nil {
			return ChallengeResult{}, discardErr
		}

		return challengeFailed(ErrSendFailed, 0), nil
	}

	s.logger.Info("telegram-2fa: code issued on demand", map[string]any{
		"user_id": identity.UserID,
	})

	now := s.clock.Now()

	return challengeSent(
		now+int64(s.config.CodeTTL.Seconds()),
		now+int64(s.config.Cooldown.Seconds()),
	), nil
}

func (s *Service) issue(userID, purpose, generation string) (code, challengeID string, err error) {
	code, err = s.codes.TwoFactorCode(s.config.CodeLength)
	if err != nil {
		return "", "", err
	}

	buf := make([]byte, 8)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}

	challengeID = hex.EncodeToString(buf)

	err = s.store.Put(
		s.config.Key("code", userID),
		map[string]any{
			// Bound to the account, so a digest lifted from the store cannot
			// be matched against another user's code.
			"hash":         s.hasher.Hash(code, userID),
			"expires_at":   s.clock.Now() + int64(s.config.CodeTTL.Seconds()),
			"attempts":     0,
			"purpose":      purpose,
			"generation":   generation,
			"challenge_id": challengeID,
		},
		s.config.CodeTTL,
	)

	return code, challengeID, err
}

// discardChallenge drops a challenge only if it is still the one we issued.
//
// A delivery failure must not delete a newer challenge. That is reachable: if
// sending blocks past the cooldown, the user can be issued a fresh code before
// this handler runs, and an unconditional delete would throw away a code the
// user is holding.
func (s *Service) discardChallenge(userID, challengeID string) error {
	key := s.config.Key("code", userID)

	raw, err := s.store.Take(key)
	if err != nil {
		return err
	}

	record := asRecord(raw)
	if record == nil {
		return nil
	}

	if recordString(record, "challenge_id") != challengeID {
		// Someone else's challenge. Put it back as we found it.
		remaining := recordInt(record, "expires_at") - s.clock.Now()
		if remaining < 1 {
			remaining = 1
		}

		return s.store.Put(key, record, time.Duration(remaining)*time.Second)
	}

	return s.store.Forget(s.config.Key("cooldown", userID))
}

// reserveSend reserves the right to send, atomically.
//
// Checking for a cooldown and then writing one is two operations, and two
// challenges arriving together both see no cooldown and both send. Add makes
// the write itself the check. It returns 0 when the caller won.
func (s *Service) reserveSend(userID string) (int64, error) {
	key := s.config.Key("cooldown", userID)
	nextSendAt := s.clock.Now() + int64(s.config.Cooldown.Seconds())

	won, err := s.store.Add(key, nextSendAt, s.config.Cooldown)
	if err != nil {
		return 0, err
	}

	if won {
		return 0, nil
	}

	held, err := s.store.Get(key)
	if err != nil {
		return 0, err
	}

	// Coerced, not type-asserted: a store may hand back a numeric string.
	if seconds, ok := asInt64(held); ok {
		return seconds, nil
	}

	return nextSendAt, nil
}

func (s *Service) clearPending(userID string) error {
	if err := s.store.Forget(s.config.Key("code", userID)); err != nil {
		return err
	}

	return s.store.Forget(s.config.Key("cooldown", userID))
}

// ------------------------------------------------------------ verification

// Verify checks a submitted code.
//
// Single use on success, attempt-budgeted on failure, constant-time throughout.
// purpose must match what the code was issued for; an empty string means
// PurposeLogin, exactly as Push defaults. There is deliberately no way to skip
// the check, because a default of "compare against nothing" means the binding
// does nothing unless every call site opts in, and the call site that forgets
// is the one that matters.
func (s *Service) Verify(userID, code, purpose string) (VerificationResult, error) {
	if purpose == "" {
		purpose = PurposeLogin
	}

	key := s.config.Key("code", userID)

	// Take the record, rather than read it and delete it later. Those are two
	// operations with a gap between them, and two verifications arriving
	// together both read the live record, both match, and both succeed — a
	// single-use code used twice, with the attempt counter losing increments
	// to the same race.
	raw, err := s.store.Take(key)
	if err != nil {
		return VerificationResult{}, err
	}

	record := asRecord(raw)
	storedHash := recordString(record, "hash")

	if record == nil || storedHash == "" {
		return verificationFailed(ErrExpired, 0), nil
	}

	attempts := int(recordInt(record, "attempts"))

	// The record is already gone in each of these branches, which is what we
	// want: a spent or expired code should not come back.
	if attempts >= s.config.MaxAttempts {
		return verificationFailed(ErrTooManyAttempts, 0), nil
	}

	if recordInt(record, "expires_at") < s.clock.Now() {
		return verificationFailed(ErrExpired, 0), nil
	}

	// The enrollment this challenge belongs to must still be current. Anything
	// that changed it revoked this challenge, and the record is already gone
	// because we took it. This check, not the cleanup in bind, is what makes
	// revocation sound: cleanup races a concurrent verification, this cannot.
	matches, err := s.generationMatches(userID, record)
	if err != nil {
		return VerificationResult{}, err
	}

	if !matches {
		s.logger.Warn("telegram-2fa: challenge from a superseded enrollment", map[string]any{
			"user_id": userID,
		})

		return verificationFailed(ErrExpired, 0), nil
	}

	if !s.purposeSatisfied(recordString(record, "purpose"), purpose) {
		// A code minted to confirm a login should not also confirm a
		// withdrawal. Count it as an attempt rather than a free retry, and
		// report invalid: telling the caller a live code exists for some other
		// purpose is information it has not proved it should have.
		return s.recordFailedAttempt(key, record, attempts, userID)
	}

	if !s.hasher.Matches(storedHash, strings.TrimSpace(code), userID) {
		return s.recordFailedAttempt(key, record, attempts, userID)
	}

	s.logger.Info("telegram-2fa: verified", map[string]any{
		"user_id": userID,
		"purpose": recordString(record, "purpose"),
	})

	return verificationPassed(), nil
}

func (s *Service) purposeSatisfied(stored, requested string) bool {
	if stored == requested {
		return true
	}

	if stored != PurposeOnDemand {
		return false
	}

	if s.config.OnDemandSatisfies == nil {
		return true
	}

	for _, allowed := range s.config.OnDemandSatisfies {
		if allowed == requested {
			return true
		}
	}

	return false
}

// generationMatches reports whether a challenge belongs to the current
// enrollment.
//
// A challenge issued before the generation existed (a row migrated from an
// older version) is accepted only while the account has no generation at all,
// so upgrading does not invalidate codes in flight.
func (s *Service) generationMatches(userID string, record map[string]any) (bool, error) {
	identity, err := s.identities.FindByUserID(userID)
	if err != nil {
		return false, err
	}

	current := ""
	if identity != nil {
		current = identity.Generation
	}

	stored := recordString(record, "generation")

	if current == "" {
		return stored == "", nil
	}

	return hmac.Equal([]byte(current), []byte(stored)), nil
}

func (s *Service) generationIsCurrent(userID, generation string) (bool, error) {
	if generation == "" {
		return false, nil
	}

	identity, err := s.identities.FindByUserID(userID)
	if err != nil {
		return false, err
	}

	if !identity.IsVerified() || identity.Generation == "" {
		return false, nil
	}

	return hmac.Equal([]byte(identity.Generation), []byte(generation)), nil
}

func (s *Service) recordFailedAttempt(
	key string, record map[string]any, attempts int, userID string,
) (VerificationResult, error) {
	spent := attempts + 1
	remaining := s.config.MaxAttempts - spent

	if remaining <= 0 {
		return verificationFailed(ErrTooManyAttempts, 0), nil
	}

	// Re-store under the code's own remaining lifetime. A fresh full TTL would
	// let an attacker keep a code alive indefinitely by guessing wrong,
	// removing the time limit altogether.
	//
	// A revocation can land between the take above and this write, so this
	// re-check keeps a dead challenge from being written back. It is
	// best-effort by nature, and does not need to be airtight, because Verify
	// re-checks the generation before accepting anything. A resurrected record
	// is inert.
	matches, err := s.generationMatches(userID, record)
	if err != nil {
		return VerificationResult{}, err
	}

	if matches {
		updated := make(map[string]any, len(record))
		for k, v := range record {
			updated[k] = v
		}

		updated["attempts"] = spent

		lifetime := recordInt(record, "expires_at") - s.clock.Now()
		if lifetime < 1 {
			lifetime = 1
		}

		if err := s.store.Put(key, updated, time.Duration(lifetime)*time.Second); err != nil {
			return VerificationResult{}, err
		}
	}

	return verificationFailed(ErrInvalid, remaining), nil
}

// --------------------------------------------------------------- unlinking

// Unlink removes the factor, proving possession of it first.
//
// Unlinking is the step an attacker with a stolen session but no phone needs,
// so it demands the same proof as any other protected action.
func (s *Service) Unlink(userID, code string) (VerificationResult, error) {
	identity, err := s.identities.FindByUserID(userID)
	if err != nil {
		return VerificationResult{}, err
	}

	if !identity.IsVerified() {
		return verificationFailed(ErrNotLinked, 0), nil
	}

	// Under PurposeUnlink, so a code pushed for a login cannot remove the
	// factor. A code the user fetched with /code still works, because
	// on-demand codes are general-purpose.
	result, err := s.Verify(userID, code, PurposeUnlink)
	if err != nil || !result.OK {
		return result, err
	}

	detached, err := s.detach(identity, identity.Generation)
	if err != nil {
		return VerificationResult{}, err
	}

	if !detached {
		// The enrollment moved while we were verifying, so the code we just
		// accepted no longer refers to what is stored.
		return verificationFailed(ErrExpired, 0), nil
	}

	return verificationPassed(), nil
}

// UnlinkAfterExternalProof removes the factor when another factor has already
// proved the request.
//
// For recovery paths: the user still has their authenticator, or passed an
// out-of-band check, but has lost the Telegram account. The caller takes
// responsibility for that proof — this method performs none.
func (s *Service) UnlinkAfterExternalProof(userID, reason string) (bool, error) {
	identity, err := s.identities.FindByUserID(userID)
	if err != nil {
		return false, err
	}

	if identity == nil {
		return false, nil
	}

	// Unconditional: the caller has proved identity by other means, and a
	// recovery must not be blocked by whatever the account's state is.
	if _, err := s.detach(identity, AnyGeneration); err != nil {
		return false, err
	}

	s.logger.Warn("telegram-2fa: unlinked via external proof", map[string]any{
		"user_id": userID,
		"reason":  reason,
	})

	return true, nil
}

// detach removes the enrollment and revokes everything that referred to it.
//
// The generation is advanced even though no chat remains, which is the whole
// reason it is stored separately from the chat id: a replacement token or a
// challenge minted before this point stays void afterwards, and would otherwise
// come back to life the moment the user links again.
func (s *Service) detach(identity *Identity, expected string) (bool, error) {
	next, err := s.codes.EnrollmentGeneration()
	if err != nil {
		return false, err
	}

	moved, err := s.identities.Transition(identity.UserID, "", expected, next)
	if err != nil {
		return false, err
	}

	if moved == nil {
		s.logger.Warn("telegram-2fa: enrollment changed during unlink", map[string]any{
			"user_id": identity.UserID,
		})

		return false, nil
	}

	if err := s.clearPending(identity.UserID); err != nil {
		return false, err
	}

	// Best effort: the user should hear that their factor was removed even if,
	// especially if, they did not do it themselves.
	if identity.ChatID != "" {
		//nolint:errcheck // best effort; the unlink has already applied
		s.telegram.SendMessage(identity.ChatID, s.messages.Unlinked(s.config.AppName), nil)
	}

	s.logger.Info("telegram-2fa: unlinked", map[string]any{"user_id": identity.UserID})

	return true, nil
}

// ------------------------------------------------------------ record access

// asRecord normalises what a store hands back into a map.
//
// A store that round-trips through JSON returns map[string]any; one that keeps
// Go values returns whatever was put in. Both are accepted so the same service
// works over Redis and over a map.
func asRecord(raw any) map[string]any {
	if record, ok := raw.(map[string]any); ok {
		return record
	}

	return nil
}

func recordString(record map[string]any, key string) string {
	if record == nil {
		return ""
	}

	if value, ok := record[key].(string); ok {
		return value
	}

	return ""
}

func recordBool(record map[string]any, key string) bool {
	if record == nil {
		return false
	}

	value, _ := record[key].(bool)

	return value
}

// recordInt coerces rather than type-asserting, because a store is not obliged
// to preserve numeric types: JSON round-trips an int as a float64, and some
// drivers return numerics as strings.
func recordInt(record map[string]any, key string) int64 {
	if record == nil {
		return 0
	}

	value, _ := asInt64(record[key])

	return value
}

func asInt64(raw any) (int64, bool) {
	switch value := raw.(type) {
	case int:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		return int64(value), true
	case string:
		parsed, err := strconv.ParseInt(value, 10, 64)

		return parsed, err == nil
	}

	return 0, false
}
