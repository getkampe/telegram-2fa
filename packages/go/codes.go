package telegram2fa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// LinkAlphabet is Crockford base32: no I, L, O or U, so there is no 1/I or 0/O
// confusion when someone reads a code off one screen and types it into another.
const LinkAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// TokenAlphabet is URL-safe, for deeplink nonces that are never retyped.
const TokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

// CodeGenerator produces the kinds of secret this protocol uses.
//
// Everything here draws from crypto/rand. math/rand is a seeded PRNG: its
// output is predictable from prior samples, which for a 2FA code means an
// attacker who has seen enough codes can produce the next one.
type CodeGenerator struct{}

// TwoFactorCode returns a numeric code, zero-padded.
//
// Numeric is safe for this one because the store key is scoped to a single user
// (SPEC.md section 6), so guessing is bounded by the attempt budget rather than
// by the size of the alphabet.
func (g CodeGenerator) TwoFactorCode(length int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("telegram2fa: generating a code: %w", err)
	}

	return fmt.Sprintf("%0*d", length, n), nil
}

// LinkCode returns a code for the paste flow.
//
// Not numeric: the paste flow's store key is derived from the code itself, so
// every outstanding code shares one namespace. Eight base32 characters is 40
// bits.
func (g CodeGenerator) LinkCode(length int) (string, error) {
	return g.fromAlphabet(LinkAlphabet, length)
}

// DeepLinkToken returns a nonce. 32 characters of a 64-symbol alphabet is 192 bits.
func (g CodeGenerator) DeepLinkToken() (string, error) {
	return g.fromAlphabet(TokenAlphabet, 32)
}

// WebhookSecret returns a secret token in the character set Telegram accepts.
func (g CodeGenerator) WebhookSecret() (string, error) {
	return g.fromAlphabet(TokenAlphabet, 48)
}

// EnrollmentGeneration returns a fresh enrollment generation: 128 bits, hex.
//
// Random rather than a counter: nothing needs ordering, only inequality, and a
// random value cannot be predicted from the ones before it.
func (g CodeGenerator) EnrollmentGeneration() (string, error) {
	buf := make([]byte, 16)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("telegram2fa: generating a generation: %w", err)
	}

	return hex.EncodeToString(buf), nil
}

func (g CodeGenerator) fromAlphabet(alphabet string, length int) (string, error) {
	var out strings.Builder
	out.Grow(length)

	max := big.NewInt(int64(len(alphabet)))

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("telegram2fa: generating a token: %w", err)
		}

		out.WriteByte(alphabet[n.Int64()])
	}

	return out.String(), nil
}

// CodeHasher hashes and compares code material.
//
// A fast keyed hash is the right primitive and not a shortcut. These codes live
// for minutes, are single-use, and are bounded by an attempt limit; a password
// KDF would add latency to every verification and buy nothing against a
// six-digit input.
//
// What does the work is the key, not the hash. A six-digit code has only a
// million possible values, so an unkeyed SHA-256 of one is reversed by a table
// anyone can build in seconds — which is why the pepper is required rather than
// recommended, and why the application's own secret must not live in the same
// store as the hashes.
//
// The context argument binds a digest to the account it belongs to, so a stolen
// digest cannot be matched against another user's, and an attacker who dumps
// the store needs a fresh search per account rather than one table for all.
type CodeHasher struct {
	newHash func() hash.Hash
	pepper  []byte
}

// NewCodeHasher returns a hasher for the named algorithm.
func NewCodeHasher(algorithm, pepper string) (*CodeHasher, error) {
	var newHash func() hash.Hash

	switch algorithm {
	case "sha256":
		newHash = sha256.New
	case "sha384":
		newHash = sha512.New384
	case "sha512":
		newHash = sha512.New
	default:
		return nil, &ConfigError{Field: "HashAlgorithm", Reason: "unknown algorithm " + algorithm}
	}

	return &CodeHasher{newHash: newHash, pepper: []byte(pepper)}, nil
}

// Hash returns the HMAC over context + NUL + code.
//
// The NUL separator means ("ab", "c") and ("a", "bc") cannot produce the same
// input; neither value can contain a NUL byte.
func (h *CodeHasher) Hash(code, context string) string {
	mac := hmac.New(h.newHash, h.pepper)
	mac.Write([]byte(context))
	mac.Write([]byte{0})
	mac.Write([]byte(code))

	return hex.EncodeToString(mac.Sum(nil))
}

// Matches compares a candidate against a stored hash in constant time.
//
// hmac.Equal, not ==. On secret material a comparison that returns at the first
// differing byte is a timing oracle.
func (h *CodeHasher) Matches(storedHash, candidate, context string) bool {
	return hmac.Equal([]byte(storedHash), []byte(h.Hash(candidate, context)))
}
