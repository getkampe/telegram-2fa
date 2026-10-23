# frozen_string_literal: true

module Kampe
  module TelegramTwoFactor
    # The error vocabulary of SPEC.md section 10.
    #
    # These strings are the wire form of the protocol, shared with every other
    # implementation, so a client written against them works against any of
    # them. Do not change the values.
    module ErrorCode
      # The account has no verified Telegram link.
      NOT_LINKED = "not_linked"
      # The account, or the chat, is already linked.
      ALREADY_LINKED = "already_linked"
      # A code was sent too recently; the result carries the next send time.
      COOLDOWN = "cooldown"
      # Telegram did not accept the message.
      SEND_FAILED = "send_failed"
      # The submitted code does not match.
      INVALID = "invalid"
      # No live code: never issued, aged out, or already used.
      EXPIRED = "expired"
      # The attempt budget for this code is exhausted.
      TOO_MANY_ATTEMPTS = "too_many_attempts"
      # Link token unknown, expired or already used.
      INVALID_TOKEN = "invalid_token"
      # Webhook secret token missing or wrong.
      WEBHOOK_UNAUTHORIZED = "webhook_unauthorized"

      # Messages safe to show an end user.
      #
      # Deliberately vague about which of "never issued", "expired" and
      # "already used" applies, because distinguishing them tells an attacker
      # holding a session whether a challenge is in flight.
      MESSAGES = {
        NOT_LINKED => "No Telegram account is linked to this profile.",
        ALREADY_LINKED => "This Telegram account is already linked.",
        COOLDOWN => "A code was just sent. Please wait before requesting another.",
        SEND_FAILED => "The code could not be delivered. Please try again or use another method.",
        INVALID => "That code is not valid.",
        EXPIRED => "That code is no longer valid. Request a new one.",
        TOO_MANY_ATTEMPTS => "Too many incorrect attempts. Request a new code.",
        INVALID_TOKEN => "This link has expired or has already been used.",
        WEBHOOK_UNAUTHORIZED => "Unauthorized."
      }.freeze

      def self.message(code)
        MESSAGES.fetch(code, "Verification failed.")
      end
    end

    # Base class for every error this library raises.
    class Error < StandardError; end

    # The configuration cannot produce a secure installation.
    #
    # Raised when the config is built, never mid-request.
    class ConfigurationError < Error; end

    # Telegram refused a request, or could not be reached.
    class RequestFailed < Error; end

    # A chat is already bound to a different account.
    #
    # Identity stores raise this rather than reassigning: one Telegram account
    # acting as the second factor for several accounts means one compromised
    # Telegram account compromises all of them.
    class ChatAlreadyLinked < Error; end
  end
end
