# frozen_string_literal: true

require "openssl"
require "securerandom"

module Kampe
  module TelegramTwoFactor
    # Crockford base32: no I, L, O or U, so there is no 1/I or 0/O confusion
    # when someone reads a code off one screen and types it into another.
    LINK_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    # URL-safe alphabet for deeplink nonces, which are never retyped by hand.
    TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

    # Generates the kinds of secret this protocol uses.
    #
    # Everything here draws from SecureRandom. Kernel#rand and Random are
    # Mersenne Twisters: their output is predictable from prior samples, which
    # for a 2FA code means an attacker who has seen enough codes can produce
    # the next one. They are not faster in any way that matters here.
    class CodeGenerator
      # A numeric 2FA code, zero-padded.
      #
      # Numeric is safe for this one because the store key is scoped to a
      # single user (SPEC.md section 6), so guessing is bounded by the attempt
      # budget rather than by the size of the alphabet.
      def two_factor_code(length = 6)
        SecureRandom.random_number(10**length).to_s.rjust(length, "0")
      end

      # A link code for the paste flow.
      #
      # Not numeric: the paste flow's store key is derived from the code
      # itself, so every outstanding code shares one namespace. Eight base32
      # characters is 40 bits.
      def link_code(length = 8)
        from_alphabet(LINK_ALPHABET, length)
      end

      # A deeplink nonce. 32 characters of a 64-symbol alphabet is 192 bits.
      def deep_link_token(length = 32)
        from_alphabet(TOKEN_ALPHABET, length)
      end

      # A webhook secret token, in the character set Telegram accepts.
      def webhook_secret(length = 48)
        from_alphabet(TOKEN_ALPHABET, length)
      end

      # A fresh enrollment generation: 128 bits, hex.
      #
      # Random rather than a counter: nothing needs ordering, only inequality,
      # and a random value cannot be predicted from the ones before it.
      def enrollment_generation
        SecureRandom.hex(16)
      end

      # Identifies one particular challenge, so a cleanup for a failed delivery
      # can tell its own code from a newer one.
      def challenge_id
        SecureRandom.hex(8)
      end

      private

      def from_alphabet(alphabet, length)
        Array.new(length) { alphabet[SecureRandom.random_number(alphabet.length)] }.join
      end
    end

    # Hashing and comparison of code material.
    #
    # A fast keyed hash is the right primitive and not a shortcut. These codes
    # live for minutes, are single-use, and are bounded by an attempt limit; a
    # password KDF would add latency to every verification and buy nothing
    # against a six-digit input.
    #
    # What does the work is the key, not the hash. A six-digit code has only a
    # million possible values, so an unkeyed SHA-256 of one is reversed by a
    # table anyone can build in seconds - which is why the pepper is required
    # rather than recommended, and why the application's own secret must not
    # live in the same store as the hashes.
    #
    # The context argument binds a digest to the account it belongs to, so a
    # stolen digest cannot be matched against another user's, and an attacker
    # who dumps the store needs a fresh search per account rather than one
    # table for all of them.
    class CodeHasher
      def initialize(algorithm = "sha256", pepper = "")
        @algorithm = algorithm
        @pepper = pepper
      end

      # HMAC over context + NUL + code.
      #
      # The NUL separator means ("ab", "c") and ("a", "bc") cannot produce the
      # same input; neither value can contain a NUL byte.
      def hash(code, context = "")
        OpenSSL::HMAC.hexdigest(@algorithm, @pepper, "#{context}\0#{code}")
      end

      # Constant-time comparison.
      #
      # secure_compare, not ==. On secret material a comparison that returns at
      # the first differing byte is a timing oracle.
      def matches?(stored_hash, candidate, context = "")
        expected = stored_hash.to_s
        actual = hash(candidate, context)

        return false unless expected.bytesize == actual.bytesize

        OpenSSL.secure_compare(expected, actual)
      end
    end
  end
end
