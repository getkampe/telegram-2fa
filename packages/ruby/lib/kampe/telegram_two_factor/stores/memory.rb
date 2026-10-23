# frozen_string_literal: true

module Kampe
  module TelegramTwoFactor
    module Stores
      # An in-process code store, for tests and single-process scripts.
      #
      # Not for production behind more than one process: each would hold its own
      # copy, so a code issued by one request would be invisible to the next.
      # Use Redis, or a table with an expires_at column.
      #
      # **Why every mutation holds the mutex.** MRI's global lock does not make
      # a read-modify-write sequence atomic: the interpreter can switch threads
      # between any two operations, so two threads can both read a record before
      # either deletes it - and then a single-use code is used twice and the
      # attempt counter loses increments. The Mutex is what actually serialises
      # them, and the tests spawn real threads to prove it.
      class Memory
        def initialize(clock = nil)
          @clock = clock || SystemClock.new
          @items = {}
          @mutex = Mutex.new
        end

        def get(key)
          @mutex.synchronize { read(key) }
        end

        def put(key, value, ttl_seconds)
          @mutex.synchronize { @items[key] = [value, @clock.now + ttl_seconds] }
          nil
        end

        def forget(key)
          @mutex.synchronize { @items.delete(key) }
          nil
        end

        # Atomically read a value and remove it.
        #
        # Exactly one caller may receive a given value. This is what makes a
        # code single-use under concurrency: the winner holds the only copy and
        # either accepts it or writes it back with one more attempt spent.
        def take(key)
          @mutex.synchronize do
            value = read(key)
            @items.delete(key)
            value
          end
        end

        # Atomically write only if the key is absent, reporting whether it did.
        #
        # The boolean is the point: it makes the write a reservation exactly one
        # caller can win, which is how the cooldown and the webhook's
        # idempotency claim avoid check-then-write races.
        def add(key, value, ttl_seconds)
          @mutex.synchronize do
            next false unless read(key).nil?

            @items[key] = [value, @clock.now + ttl_seconds]
            true
          end
        end

        private

        # Caller must hold the mutex.
        def read(key)
          item = @items[key]

          return nil if item.nil?

          value, expires_at = item

          if expires_at <= @clock.now
            @items.delete(key)

            return nil
          end

          value
        end
      end

      # An in-memory identity store, for tests and for sketching an integration
      # before wiring it to a database.
      #
      # It models both rules a real store must enforce: one chat belongs to one
      # account, and a transition only applies when the stored generation is the
      # one the caller expected. Rows survive unlinking, because the generation
      # has to.
      class MemoryIdentities
        def initialize(clock = nil)
          @clock = clock || SystemClock.new
          @rows = {}
          @mutex = Mutex.new
        end

        def find_by_user_id(user_id)
          @mutex.synchronize { @rows[user_id] }
        end

        def find_by_chat_id(chat_id)
          @mutex.synchronize { by_chat_id(chat_id) }
        end

        # Compare-and-set the enrollment.
        #
        # +expected+ is the generation the caller believes is current; nil means
        # "none recorded yet"; ANY_GENERATION skips the check. Returns nil when
        # the expectation did not hold, leaving the row exactly as it was.
        def transition(user_id, chat_id, expected, next_generation)
          @mutex.synchronize do
            current = @rows[user_id]

            # The expectation failed, so the stored row is left exactly as it
            # was. Returning nil rather than raising lets the caller decide
            # whether this is a conflict or a stale token.
            next nil if expected != ANY_GENERATION && current&.generation != expected

            unless chat_id.nil?
              holder = by_chat_id(chat_id)

              if !holder.nil? && holder.user_id != user_id
                raise ChatAlreadyLinked,
                      "That Telegram chat is already the second factor for another account."
              end
            end

            identity = Identity.new(
              user_id: user_id,
              chat_id: chat_id,
              linked_at: chat_id.nil? ? nil : @clock.now,
              generation: next_generation
            )

            @rows[user_id] = identity
            identity
          end
        end

        # Test helper: seed a verified enrollment without going through a flow.
        def seed(user_id, chat_id, generation)
          @mutex.synchronize do
            @rows[user_id] = Identity.new(
              user_id: user_id, chat_id: chat_id,
              linked_at: @clock.now, generation: generation
            )
          end
        end

        private

        # Caller must hold the mutex.
        def by_chat_id(chat_id)
          @rows.each_value do |identity|
            return identity if !identity.chat_id.nil? && identity.chat_id == chat_id
          end

          nil
        end
      end
    end
  end
end
