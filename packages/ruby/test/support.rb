# frozen_string_literal: true

require "minitest/autorun"
require "kampe/telegram_two_factor"

module TestSupport
  include Kampe::TelegramTwoFactor

  CODE_PATTERN = %r{<code>([^<]+)</code>}

  # Records what it was asked to send.
  class FakeTelegram
    attr_accessor :should_fail_sending
    attr_reader :sent, :answered

    def initialize
      @sent = []
      @answered = []
      @should_fail_sending = false
      @during_next_failure = nil
      @mutex = Mutex.new
    end

    # Fail the next send, running +block+ while it is "in flight".
    #
    # Models a send that blocks long enough for the world to move on - the
    # cooldown lapsing and another challenge being issued - before the failure
    # is reported and its cleanup runs.
    def fail_next_send(&block)
      @should_fail_sending = true
      @during_next_failure = block
    end

    def send_message(chat_id, text, _inline_keyboard = nil)
      if @should_fail_sending
        if @during_next_failure
          # One-shot: the hook models a single slow, failing send, and the
          # sends it triggers must succeed.
          during = @during_next_failure
          @during_next_failure = nil
          @should_fail_sending = false
          during.call
        end

        return false
      end

      @mutex.synchronize { @sent << { chat_id: chat_id, text: text } }

      true
    end

    def answer_callback_query(id, _text = nil)
      @mutex.synchronize { @answered << id }

      true
    end

    def get_me = { "username" => "kampe_test_bot" }
    def set_webhook(*) = true
    def delete_webhook = true

    def last_message
      @mutex.synchronize { @sent.empty? ? "" : @sent.last[:text] }
    end

    def last_sent_to
      @mutex.synchronize { @sent.empty? ? nil : @sent.last[:chat_id] }
    end

    def reset
      @mutex.synchronize do
        @sent = []
        @answered = []
      end
    end
  end

  # A clock that yields the scheduler whenever it is read.
  #
  # Threads alone are not enough to expose a missing mutex in MRI: the
  # interpreter switches threads only every so often, and a critical section
  # this short normally completes inside one slice, so an unlocked
  # implementation passes a threaded test most of the time. That is exactly the
  # false confidence a race test must not give.
  #
  # The store reads the clock between looking a record up and removing it, so
  # sleeping here forces the interleaving. With the mutex held the sleep is
  # harmless - other threads simply wait for it - and without the mutex a
  # second thread reads the record the first is about to delete.
  class YieldingClock
    def initialize(now = 1_700_000_000, pause = 0.005)
      @now = now
      @pause = pause
    end

    def now
      sleep(@pause)
      @now
    end

    def advance(seconds)
      @now += seconds
      self
    end
  end

  # Wraps a store, recording every call and yielding the scheduler after each
  # one returns.
  #
  # This opens a window the shipped store cannot be made to open: a pause
  # *inside* a critical section is harmless, and MRI lets the thread that
  # released a mutex re-acquire it before a woken waiter is scheduled, so a
  # service built from get-then-delete still looks atomic under a yielding
  # clock. The gap that matters is between two store calls, which is here.
  #
  # The call log is the deterministic half of the same check: a verification
  # that consumes its record in one operation can only be +take+.
  class RecordingStore
    def initialize(inner, pause = 0.002)
      @inner = inner
      @pause = pause
      @mutex = Mutex.new
      @calls = []
    end

    def calls
      @mutex.synchronize { @calls.dup }
    end

    def reset_calls
      @mutex.synchronize { @calls = [] }
    end

    %i[get put forget take add].each do |name|
      define_method(name) do |*args|
        @mutex.synchronize { @calls << name }
        result = @inner.public_send(name, *args)
        sleep(@pause)
        result
      end
    end
  end

  def make_config(**overrides)
    Config.new(**{
      bot_token: "123456789:AAFakeTokenForTestsOnly_0123456789abc",
      webhook_secret: "s" * 48,
      hash_pepper: "p" * 48,
      bot_username: "kampe_test_bot",
      app_name: "Kampe"
    }.merge(overrides))
  end

  # Run +count+ threads, released simultaneously.
  #
  # The barrier is what makes this deterministic: without it the first thread
  # usually finishes before the last one starts, and the test would pass
  # against a broken implementation most of the time.
  def race(count)
    mutex = Mutex.new
    condition = ConditionVariable.new
    waiting = 0
    released = false
    results = Array.new(count)

    threads = Array.new(count) do |index|
      Thread.new do
        mutex.synchronize do
          waiting += 1
          condition.broadcast if waiting == count
          condition.wait(mutex) until released
        end

        results[index] = yield(index)
      end
    end

    mutex.synchronize do
      condition.wait(mutex) until waiting == count
      released = true
      condition.broadcast
    end

    threads.each(&:join)
    results
  end
end

# A fully wired service on in-memory parts.
class HarnessTest < Minitest::Test
  include TestSupport
  include Kampe::TelegramTwoFactor

  def setup
    super

    @clock = build_clock
    @store = Stores::Memory.new(@clock)
    @identities = Stores::MemoryIdentities.new(@clock)
    @telegram = FakeTelegram.new
    @config = make_config
    @messages = DefaultMessages.new

    @tfa = Service.new(
      config: @config, store: @store, identities: @identities,
      telegram: @telegram, messages: @messages, clock: @clock
    )
  end

  attr_reader :clock, :store, :identities, :telegram, :config, :messages, :tfa

  # Overridden by the concurrency suite, which needs a clock that yields the
  # scheduler so a critical section cannot complete inside one slice.
  def build_clock
    FrozenClock.new
  end

  # A service wired to the same parts but a different configuration.
  def with_config(**overrides)
    Service.new(
      config: make_config(**overrides), store: @store, identities: @identities,
      telegram: @telegram, messages: @messages, clock: @clock
    )
  end

  # Seed a verified enrollment without going through a link flow.
  def seed(user_id = "user-1", chat_id = "555000111")
    @identities.seed(user_id, chat_id, "gen-#{user_id}")
  end

  # The code from the most recent outgoing message.
  #
  # Tests have to recover it from the message because the library deliberately
  # never returns it.
  def last_code
    TestSupport::CODE_PATTERN.match(@telegram.last_message)&.captures&.first.to_s
  end

  def wrong_code(code)
    code == "000000" ? "111111" : "000000"
  end
end
