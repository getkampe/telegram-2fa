# frozen_string_literal: true

require "openssl"

module Kampe
  module TelegramTwoFactor
    # Validated configuration.
    #
    # The constructor rejects a configuration that cannot be secure, rather
    # than accepting it and logging a warning nobody reads. A missing webhook
    # secret is the clearest case: with one absent, the webhook is an open
    # endpoint that will mint a code for any chat id a stranger posts to it,
    # and the application looks like it works. Failing at startup is the only
    # version of that outcome anyone notices.
    class Config
      BOT_TOKEN_PATTERN = /\A\d+:[A-Za-z0-9_-]{30,}\z/
      WEBHOOK_SECRET_PATTERN = /\A[A-Za-z0-9_-]{32,256}\z/
      BOT_USERNAME_PATTERN = /\A[A-Za-z0-9_]{5,32}\z/

      attr_reader :bot_token, :webhook_secret, :hash_pepper, :bot_username, :app_name,
                  :code_length, :code_ttl, :cooldown, :max_attempts,
                  :link_code_length, :link_ttl, :key_prefix, :hash_algorithm,
                  :dedupe_updates, :update_dedupe_ttl, :restrict_webhook_ips,
                  :on_demand_satisfies

      def initialize(
        bot_token:,
        webhook_secret:,
        hash_pepper:,
        bot_username: nil,
        app_name: "Kampe",
        code_length: 6,
        code_ttl: 300,
        cooldown: 120,
        max_attempts: 5,
        link_code_length: 8,
        link_ttl: 600,
        key_prefix: "tg2fa",
        hash_algorithm: "sha256",
        dedupe_updates: true,
        update_dedupe_ttl: 3600,
        restrict_webhook_ips: false,
        on_demand_satisfies: nil
      )
        @bot_token = bot_token.to_s
        @webhook_secret = webhook_secret.to_s
        @hash_pepper = hash_pepper.to_s
        @bot_username = bot_username
        @app_name = app_name
        @code_length = code_length
        @code_ttl = code_ttl
        @cooldown = cooldown
        @max_attempts = max_attempts
        @link_code_length = link_code_length
        @link_ttl = link_ttl
        @key_prefix = key_prefix
        @hash_algorithm = hash_algorithm
        @dedupe_updates = dedupe_updates
        @update_dedupe_ttl = update_dedupe_ttl
        @restrict_webhook_ips = restrict_webhook_ips
        @on_demand_satisfies = on_demand_satisfies

        validate!
      end

      # Build from environment variables, for the common case.
      def self.from_env(env = ENV)
        new(
          bot_token: env["TELEGRAM_BOT_TOKEN"].to_s,
          webhook_secret: env["TELEGRAM_WEBHOOK_SECRET"].to_s,
          hash_pepper: env["TELEGRAM_2FA_HASH_PEPPER"].to_s,
          bot_username: presence(env["TELEGRAM_BOT_USERNAME"]),
          app_name: presence(env["TELEGRAM_2FA_APP_NAME"]) || "Kampe",
          code_ttl: integer_env(env, "TELEGRAM_2FA_CODE_TTL", 300),
          cooldown: integer_env(env, "TELEGRAM_2FA_COOLDOWN", 120),
          max_attempts: integer_env(env, "TELEGRAM_2FA_MAX_ATTEMPTS", 5)
        )
      end

      def key(kind, identifier)
        "#{@key_prefix}:#{kind}:#{identifier}"
      end

      def deep_link_url(token)
        return nil if @bot_username.nil?

        "https://t.me/#{@bot_username}?start=#{token}"
      end

      # A value suitable for the webhook secret or the hash pepper.
      def self.generate_secret
        CodeGenerator.new.webhook_secret
      end

      def self.presence(value)
        value.nil? || value.to_s.empty? ? nil : value.to_s
      end

      # Integer(), not to_i. "5 minutes".to_i is 5 and "nonsense".to_i is 0,
      # so to_i turns a typo into a silently wrong security parameter.
      def self.integer_env(env, key, fallback)
        raw = env[key]

        return fallback if raw.nil? || raw.to_s.empty?

        begin
          Integer(raw, 10)
        rescue ArgumentError, TypeError
          raise ConfigurationError,
                "#{key} must be a whole number; received #{raw.inspect}."
        end
      end

      private_class_method :presence, :integer_env

      private

      def validate!
        raise ConfigurationError, <<~MESSAGE.strip if @bot_token.strip.empty?
          A bot token is required. Create a bot with @BotFather and set TELEGRAM_BOT_TOKEN.
        MESSAGE

        unless BOT_TOKEN_PATTERN.match?(@bot_token)
          raise ConfigurationError, <<~MESSAGE.strip
            The bot token is not in the format @BotFather issues (123456789:AA...). Check that the value was not truncated or quoted.
          MESSAGE
        end

        # Telegram accepts 1 to 256 characters here. One character would
        # satisfy Telegram and defeat the purpose, so the floor is ours.
        unless WEBHOOK_SECRET_PATTERN.match?(@webhook_secret)
          raise ConfigurationError, <<~MESSAGE.strip
            The webhook secret must be 32 to 256 characters of A-Z, a-z, 0-9, underscore or hyphen. Generate one with Config.generate_secret and set TELEGRAM_WEBHOOK_SECRET. This is what stops a stranger forging updates against your webhook; it is not optional.
          MESSAGE
        end

        # Required, not recommended. A six-digit code has a million possible
        # values, so an unkeyed digest of one is reversed by a table anyone can
        # build in seconds: without a key, hashing the codes protects nothing
        # against someone who reads the store.
        if @hash_pepper.length < 32
          raise ConfigurationError, <<~MESSAGE.strip
            hash_pepper must be at least 32 characters. It is the HMAC key for code hashes, and without it a dumped cache of six-digit code hashes is reversed by a lookup table of a million entries. Keep it outside the store it protects.
          MESSAGE
        end

        if !@bot_username.nil? && !BOT_USERNAME_PATTERN.match?(@bot_username)
          raise ConfigurationError, <<~MESSAGE.strip
            The bot username must be 5 to 32 characters of A-Z, a-z, 0-9 or underscore, with no leading @.
          MESSAGE
        end

        {
          code_length: @code_length, code_ttl: @code_ttl, cooldown: @cooldown,
          max_attempts: @max_attempts, link_code_length: @link_code_length,
          link_ttl: @link_ttl, update_dedupe_ttl: @update_dedupe_ttl
        }.each { |name, value| require_whole_number!(name, value) }

        unless (6..8).cover?(@code_length)
          raise ConfigurationError, "code_length must be between 6 and 8."
        end

        unless (30..600).cover?(@code_ttl)
          raise ConfigurationError, <<~MESSAGE.strip
            code_ttl must be between 30 and 600 seconds. A code that outlives the step it authorises is a code sitting in a chat history waiting to be reused.
          MESSAGE
        end

        if @cooldown < 30
          raise ConfigurationError, <<~MESSAGE.strip
            cooldown must be at least 30 seconds, or the bot becomes a way to spam someone via your bot token.
          MESSAGE
        end

        unless (1..10).cover?(@max_attempts)
          raise ConfigurationError, <<~MESSAGE.strip
            max_attempts must be between 1 and 10. Unlimited attempts against a six-digit code is not two-factor authentication.
          MESSAGE
        end

        if @link_code_length < 8
          raise ConfigurationError, <<~MESSAGE.strip
            link_code_length must be at least 8. Paste-flow codes are stored under a key derived from the code, so they share one namespace across every user and a short code is enumerable.
          MESSAGE
        end

        unless (60..900).cover?(@link_ttl)
          raise ConfigurationError, "link_ttl must be between 60 and 900 seconds."
        end

        if @key_prefix.to_s.empty? || @key_prefix.include?(":")
          raise ConfigurationError, "key_prefix must be non-empty and must not contain a colon."
        end

        unless OpenSSL::Digest.respond_to?(:new) && digest_available?
          raise ConfigurationError, %(Unknown hash algorithm "#{@hash_algorithm}".)
        end

        validate_on_demand!
      end

      def digest_available?
        OpenSSL::Digest.new(@hash_algorithm)
        true
      rescue StandardError
        false
      end

      def validate_on_demand!
        return if @on_demand_satisfies.nil?

        if @on_demand_satisfies.empty?
          raise ConfigurationError, <<~MESSAGE.strip
            on_demand_satisfies must list at least one purpose, or be nil for any. An empty list makes every code fetched with /code useless.
          MESSAGE
        end

        return if @on_demand_satisfies.all? { |p| p.is_a?(String) && !p.empty? }

        raise ConfigurationError, "on_demand_satisfies must contain non-empty strings."
      end

      # true and false are not Integers in Ruby, unlike Python, but a Float
      # still is not a whole number and reaches Redis as an EX argument.
      def require_whole_number!(name, value)
        return if value.is_a?(Integer)

        raise ConfigurationError, "#{name} must be a whole number; received #{value.inspect}."
      end
    end
  end
end
