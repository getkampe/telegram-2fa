package telegram2fa

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	botTokenPattern     = regexp.MustCompile(`^\d+:[A-Za-z0-9_-]{30,}$`)
	webhookSecretRegexp = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
	botUsernamePattern  = regexp.MustCompile(`^[A-Za-z0-9_]{5,32}$`)
)

// Config is validated configuration.
//
// NewConfig rejects a configuration that cannot be secure, rather than
// accepting it and logging a warning nobody reads. A missing webhook secret is
// the clearest case: with one absent, the webhook is an open endpoint that will
// mint a code for any chat id a stranger posts to it, and the application looks
// like it works. Failing at startup is the only version of that outcome anyone
// notices.
type Config struct {
	BotToken      string
	WebhookSecret string
	// HashPepper is required. See CodeHasher for why an unkeyed digest of a
	// six-digit code protects nothing.
	HashPepper  string
	BotUsername string
	AppName     string

	CodeLength     int
	CodeTTL        time.Duration
	Cooldown       time.Duration
	MaxAttempts    int
	LinkCodeLength int
	LinkTTL        time.Duration

	KeyPrefix     string
	HashAlgorithm string

	DedupeUpdates      bool
	UpdateDedupeTTL    time.Duration
	RestrictWebhookIPs bool

	// OnDemandSatisfies lists which purposes a code the user fetched with
	// /code may satisfy. Nil means any: an on-demand code is general-purpose
	// because it cannot know what it is for and the user asked for it
	// deliberately. An allowlist narrows that, at the cost of needing a push
	// path for unlinking.
	OnDemandSatisfies []string
}

// NewConfig applies defaults and validates.
func NewConfig(c Config) (*Config, error) {
	if c.AppName == "" {
		c.AppName = "Kampe"
	}
	if c.CodeLength == 0 {
		c.CodeLength = 6
	}
	if c.CodeTTL == 0 {
		c.CodeTTL = 300 * time.Second
	}
	if c.Cooldown == 0 {
		c.Cooldown = 120 * time.Second
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 5
	}
	if c.LinkCodeLength == 0 {
		c.LinkCodeLength = 8
	}
	if c.LinkTTL == 0 {
		c.LinkTTL = 600 * time.Second
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = "tg2fa"
	}
	if c.HashAlgorithm == "" {
		c.HashAlgorithm = "sha256"
	}
	if c.UpdateDedupeTTL == 0 {
		c.UpdateDedupeTTL = time.Hour
	}

	if strings.TrimSpace(c.BotToken) == "" {
		return nil, &ConfigError{
			Field:  "BotToken",
			Reason: "required. Create a bot with @BotFather and set TELEGRAM_BOT_TOKEN",
		}
	}

	if !botTokenPattern.MatchString(c.BotToken) {
		return nil, &ConfigError{
			Field: "BotToken",
			Reason: "not in the format @BotFather issues (123456789:AA...). " +
				"Check that the value was not truncated or quoted",
		}
	}

	// Telegram accepts 1 to 256 characters here. One character would satisfy
	// Telegram and defeat the purpose, so the floor is ours.
	if !webhookSecretRegexp.MatchString(c.WebhookSecret) {
		return nil, &ConfigError{
			Field: "WebhookSecret",
			Reason: "must be 32 to 256 characters of A-Z, a-z, 0-9, underscore or hyphen. " +
				"Generate one with CodeGenerator{}.WebhookSecret(). This is what stops a " +
				"stranger forging updates against your webhook; it is not optional",
		}
	}

	// Required, not recommended. A six-digit code has a million possible
	// values, so an unkeyed digest of one is reversed by a table anyone can
	// build in seconds: without a key, hashing the codes protects nothing
	// against someone who reads the store.
	if len(c.HashPepper) < 32 {
		return nil, &ConfigError{
			Field: "HashPepper",
			Reason: "must be at least 32 characters. It is the HMAC key for code hashes, " +
				"and without it a dumped cache of six-digit code hashes is reversed by a " +
				"lookup table of a million entries. Keep it outside the store it protects",
		}
	}

	if c.BotUsername != "" && !botUsernamePattern.MatchString(c.BotUsername) {
		return nil, &ConfigError{
			Field:  "BotUsername",
			Reason: "must be 5 to 32 characters of A-Z, a-z, 0-9 or underscore, with no leading @",
		}
	}

	if c.CodeLength < 6 || c.CodeLength > 8 {
		return nil, &ConfigError{Field: "CodeLength", Reason: "must be between 6 and 8"}
	}

	if c.CodeTTL < 30*time.Second || c.CodeTTL > 600*time.Second {
		return nil, &ConfigError{
			Field: "CodeTTL",
			Reason: "must be between 30 and 600 seconds. A code that outlives the step it " +
				"authorises is a code sitting in a chat history waiting to be reused",
		}
	}

	if c.Cooldown < 30*time.Second {
		return nil, &ConfigError{
			Field: "Cooldown",
			Reason: "must be at least 30 seconds, or the bot becomes a way to spam someone " +
				"via your bot token",
		}
	}

	if c.MaxAttempts < 1 || c.MaxAttempts > 10 {
		return nil, &ConfigError{
			Field: "MaxAttempts",
			Reason: "must be between 1 and 10. Unlimited attempts against a six-digit code " +
				"is not two-factor authentication",
		}
	}

	if c.LinkCodeLength < 8 {
		return nil, &ConfigError{
			Field: "LinkCodeLength",
			Reason: "must be at least 8. Paste-flow codes are stored under a key derived " +
				"from the code, so they share one namespace across every user and a short " +
				"code is enumerable",
		}
	}

	if c.LinkTTL < 60*time.Second || c.LinkTTL > 900*time.Second {
		return nil, &ConfigError{Field: "LinkTTL", Reason: "must be between 60 and 900 seconds"}
	}

	if c.KeyPrefix == "" || strings.Contains(c.KeyPrefix, ":") {
		return nil, &ConfigError{
			Field:  "KeyPrefix",
			Reason: "must be non-empty and must not contain a colon",
		}
	}

	if c.OnDemandSatisfies != nil {
		if len(c.OnDemandSatisfies) == 0 {
			return nil, &ConfigError{
				Field: "OnDemandSatisfies",
				Reason: "must list at least one purpose, or be nil for any. An empty list " +
					"makes every code fetched with /code useless",
			}
		}

		for _, purpose := range c.OnDemandSatisfies {
			if purpose == "" {
				return nil, &ConfigError{
					Field:  "OnDemandSatisfies",
					Reason: "must contain non-empty strings",
				}
			}
		}
	}

	// Validated once, so the hasher cannot fail later.
	if _, err := NewCodeHasher(c.HashAlgorithm, c.HashPepper); err != nil {
		return nil, err
	}

	return &c, nil
}

// ConfigFromEnv builds from environment variables, for the common case.
func ConfigFromEnv() (*Config, error) {
	seconds := func(key string, fallback time.Duration) (time.Duration, error) {
		raw := os.Getenv(key)

		if raw == "" {
			return fallback, nil
		}

		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, &ConfigError{Field: key, Reason: "must be a whole number of seconds"}
		}

		return time.Duration(n) * time.Second, nil
	}

	codeTTL, err := seconds("TELEGRAM_2FA_CODE_TTL", 300*time.Second)
	if err != nil {
		return nil, err
	}

	cooldown, err := seconds("TELEGRAM_2FA_COOLDOWN", 120*time.Second)
	if err != nil {
		return nil, err
	}

	attempts := 5

	if raw := os.Getenv("TELEGRAM_2FA_MAX_ATTEMPTS"); raw != "" {
		attempts, err = strconv.Atoi(raw)
		if err != nil {
			return nil, &ConfigError{
				Field:  "TELEGRAM_2FA_MAX_ATTEMPTS",
				Reason: "must be a whole number",
			}
		}
	}

	return NewConfig(Config{
		BotToken:      os.Getenv("TELEGRAM_BOT_TOKEN"),
		WebhookSecret: os.Getenv("TELEGRAM_WEBHOOK_SECRET"),
		HashPepper:    os.Getenv("TELEGRAM_2FA_HASH_PEPPER"),
		BotUsername:   os.Getenv("TELEGRAM_BOT_USERNAME"),
		AppName:       os.Getenv("TELEGRAM_2FA_APP_NAME"),
		CodeTTL:       codeTTL,
		Cooldown:      cooldown,
		MaxAttempts:   attempts,
		DedupeUpdates: true,
	})
}

// Key returns the namespaced store key for a kind and identifier.
func (c *Config) Key(kind, identifier string) string {
	return c.KeyPrefix + ":" + kind + ":" + identifier
}

// DeepLinkURL returns the t.me link for a token, or "" when the bot username
// is unknown.
func (c *Config) DeepLinkURL(token string) string {
	if c.BotUsername == "" {
		return ""
	}

	return "https://t.me/" + c.BotUsername + "?start=" + token
}
