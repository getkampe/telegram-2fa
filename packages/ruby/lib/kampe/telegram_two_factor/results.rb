# frozen_string_literal: true

module Kampe
  module TelegramTwoFactor
    # The outcome of asking for a code to be issued and delivered.
    #
    # Note what is absent: the code. Neither challenge direction returns it,
    # which is the only reason a result like this can be serialised straight
    # into an HTTP response.
    class ChallengeResult
      attr_reader :error, :expires_at, :next_send_at

      def initialize(ok:, error: nil, expires_at: nil, next_send_at: nil)
        @ok = ok
        @error = error
        @expires_at = expires_at
        @next_send_at = next_send_at
        freeze
      end

      def self.sent(expires_at, next_send_at)
        new(ok: true, expires_at: expires_at, next_send_at: next_send_at)
      end

      def self.failed(error, next_send_at = nil)
        new(ok: false, error: error, next_send_at: next_send_at)
      end

      def ok?
        @ok
      end

      # Seconds to wait before offering a resend, never negative.
      def retry_after(now)
        return 0 if @next_send_at.nil?

        [0, @next_send_at - now].max
      end

      def to_h
        { ok: @ok, error: @error, expires_at: @expires_at, next_send_at: @next_send_at }
      end
    end

    # The outcome of checking a submitted code.
    class VerificationResult
      attr_reader :error, :attempts_remaining

      def initialize(ok:, error: nil, attempts_remaining: nil)
        @ok = ok
        @error = error
        @attempts_remaining = attempts_remaining
        freeze
      end

      def self.passed
        new(ok: true)
      end

      def self.failed(error, attempts_remaining = nil)
        new(ok: false, error: error, attempts_remaining: attempts_remaining)
      end

      def ok?
        @ok
      end

      def to_h
        { ok: @ok, error: @error, attempts_remaining: @attempts_remaining }
      end
    end

    # A pending link, ready to be shown to the user.
    #
    # This is the one place a secret legitimately leaves the library, because
    # the user has to receive it somehow. For the deeplink flow put +url+ in a
    # button or a QR code; for the paste flow show +token+ in the chat. Either
    # way it does not belong in a log line or an audit record.
    LinkRequest = Struct.new(:token, :expires_at, :url, keyword_init: true)

    # The outcome of resolving a link token.
    class LinkResult
      attr_reader :identity, :error

      def initialize(ok:, identity: nil, error: nil)
        @ok = ok
        @identity = identity
        @error = error
        freeze
      end

      def self.linked(identity)
        new(ok: true, identity: identity)
      end

      def self.failed(error)
        new(ok: false, error: error)
      end

      def ok?
        @ok
      end

      def to_h
        { ok: @ok, error: @error, linked_at: @identity&.linked_at }
      end
    end
  end
end
