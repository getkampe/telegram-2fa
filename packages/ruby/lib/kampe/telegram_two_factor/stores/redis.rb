# frozen_string_literal: true

require "json"

module Kampe
  module TelegramTwoFactor
    module Stores
      # A production code store on Redis.
      #
      # Values are JSON, in the key layout and the field names of SPEC.md
      # section 9, so the other implementations read and write the same records
      # against the same server.
      #
      # The client is accepted structurally, so the gem keeps no runtime
      # dependency: anything exposing +get+, +set(key, value, ex:, nx:)+, +del+
      # and either +getdel+ or +eval+ will do, which redis-rb 4.6 and later
      # does directly. A command-style client such as redis-client, which
      # speaks only +call+, needs a dozen-line wrapper - see README.md.
      #
      # TTLs are Redis's own, which is why each record also carries its
      # +expires_at+: the two must agree, and the explicit field is what keeps
      # expiry correct against a replica whose clock has drifted or a store with
      # coarse TTL granularity.
      class Redis
        # GET and DEL in one round trip, for servers older than Redis 6.2 which
        # have no GETDEL.
        TAKE_SCRIPT = <<~LUA
          local v = redis.call('GET', KEYS[1])
          if v then redis.call('DEL', KEYS[1]) end
          return v
        LUA

        def initialize(redis)
          @redis = redis
          @take = resolve_take(redis)
        end

        def get(key)
          decode(@redis.get(key))
        end

        def put(key, value, ttl_seconds)
          @redis.set(key, JSON.generate(value), ex: ttl_seconds)
          nil
        end

        def forget(key)
          @redis.del(key)
          nil
        end

        # Atomically read a value and remove it.
        #
        # Exactly one caller may receive a given value, which is what makes a
        # code single-use across processes. A two-call GET-then-DEL here would
        # let two simultaneous verifications of one code both succeed, so this
        # is resolved to a single server-side operation at construction.
        def take(key)
          decode(@take.call(key))
        end

        # Atomically write only if the key is absent, reporting whether it did.
        #
        # SET NX declines when the key already exists, which is exactly the
        # reservation semantics the cooldown and the webhook's idempotency claim
        # need.
        #
        # Both falsey forms are checked because clients disagree about which
        # they return: the server sends a null reply, redis-rb converts that to
        # +false+, and others pass the nil through. Testing only for nil would
        # read every lost reservation as won - so the cooldown would never hold
        # and the webhook would process an update twice.
        def add(key, value, ttl_seconds)
          result = @redis.set(key, JSON.generate(value), ex: ttl_seconds, nx: true)

          !result.nil? && result != false
        end

        private

        # Resolved once, at construction, so a deployment whose client cannot
        # remove a key and return its value in one operation fails here rather
        # than silently accepting one code twice under load.
        def resolve_take(redis)
          if redis.respond_to?(:getdel)
            ->(key) { redis.getdel(key) }
          elsif redis.respond_to?(:eval)
            ->(key) { redis.eval(TAKE_SCRIPT, keys: [key]) }
          else
            raise ConfigurationError,
                  "This Redis client exposes neither GETDEL nor EVAL, so it cannot remove " \
                  "a key and return its value in one operation. Without that, two " \
                  "simultaneous verifications of the same code can both succeed. Upgrade " \
                  "the client, or implement the store contract on a primitive that is atomic."
          end
        end

        def decode(raw)
          return nil if raw.nil?

          JSON.parse(raw)
        rescue JSON::ParserError
          # A value that is not JSON was not written by this library. Treating
          # it as absent is safer than raising inside a verification path.
          nil
        end
      end
    end
  end
end
