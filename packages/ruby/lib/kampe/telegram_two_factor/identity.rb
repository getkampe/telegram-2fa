# frozen_string_literal: true

module Kampe
  module TelegramTwoFactor
    # Expectation meaning "whatever is there now", for recovery paths where the
    # caller has already proved identity by other means and must not be blocked
    # by a concurrent change.
    ANY_GENERATION = "\0any"

    # An account's Telegram enrollment, as the identity store holds it.
    #
    # This represents the row rather than only the linked state, so an account
    # that has been unlinked still has an Identity - carrying no chat, but
    # carrying the generation. That is deliberate: revocation has to outlive the
    # binding it revokes, or a token minted before an unlink would come back to
    # life when the user links again.
    Identity = Struct.new(:user_id, :chat_id, :linked_at, :generation, keyword_init: true) do
      # Only a verified link counts as a second factor.
      #
      # A row carrying a chat id with no verification timestamp is a link that
      # was started and never completed. Treating it as linked would let anyone
      # who can write a chat id into the row satisfy a challenge.
      def verified?
        !chat_id.nil? && chat_id != "" && !linked_at.nil?
      end
    end

    # Convenience for the many places that must tolerate a nil identity.
    def self.verified?(identity)
      !identity.nil? && identity.verified?
    end

    # Wall clock, injectable so expiry and cooldown are testable without
    # sleeping.
    class SystemClock
      def now
        Time.now.to_i
      end
    end

    # A clock that moves only when you move it.
    #
    # Shipped in lib rather than test so applications can test their own expiry
    # handling without sleeping through it.
    class FrozenClock
      def initialize(now = 1_700_000_000)
        @now = now
      end

      attr_reader :now

      def advance(seconds)
        @now += seconds
        self
      end

      def set_to(timestamp)
        @now = timestamp
        self
      end
    end

    # Discards everything. The default, so the library never writes to a log the
    # host application did not hand it.
    #
    # Nothing passed to a logger here contains a code, a link token or a raw
    # update body - and the update body is the important one, because for this
    # bot the update body *is* the code.
    class NullLogger
      def info(message, context = {}); end
      def warn(message, context = {}); end
      def error(message, context = {}); end
    end

    # Adapts a ::Logger.
    class StdlibLogger
      def initialize(logger)
        @logger = logger
      end

      def info(message, context = {})
        @logger.info("#{message} #{context.inspect}")
      end

      def warn(message, context = {})
        @logger.warn("#{message} #{context.inspect}")
      end

      def error(message, context = {})
        @logger.error("#{message} #{context.inspect}")
      end
    end
  end
end
