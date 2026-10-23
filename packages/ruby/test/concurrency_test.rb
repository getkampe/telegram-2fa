# frozen_string_literal: true

require_relative "support"

# SPEC.md 5.1 - the state transitions that must be atomic.
#
# These use real threads against the shipped stores, released together by a
# barrier. MRI's global lock does not make a read-modify-write sequence atomic:
# the interpreter switches threads between operations, so two threads can both
# read a record before either deletes it.
#
# The YieldingClock is what makes the suite *sensitive*. Without it these tests
# pass against a store with no mutex at all, because a critical section this
# short normally completes inside one scheduling slice - the same false
# confidence the Python port's first threaded suite gave.
class MemoryStoreConcurrencyTest < Minitest::Test
  include TestSupport
  include Kampe::TelegramTwoFactor

  # The sensitivity check for everything else in this class.
  def test_a_missing_mutex_would_be_caught
    store = Stores::Memory.new(YieldingClock.new)
    store.put("k", "value", 60)

    results = race(8) { store.take("k") }

    assert_equal 1, results.compact.length,
                 "exactly one caller may receive the value, even when the " \
                 "critical section is forced to yield"
  end

  def test_add_is_atomic_when_forced_to_yield
    store = Stores::Memory.new(YieldingClock.new)

    results = race(8) { |index| store.add("k", index, 60) }

    assert_equal 1, results.count(true), "exactly one reservation may win"
  end

  def test_only_one_of_many_concurrent_takes_gets_the_value
    store = Stores::Memory.new(FrozenClock.new)
    store.put("k", "value", 60)

    results = race(16) { store.take("k") }

    assert_equal ["value"], results.compact
  end

  def test_a_reservation_loser_does_not_overwrite_the_winner
    store = Stores::Memory.new(FrozenClock.new)
    store.add("k", "first", 60)

    race(8) { |index| store.add("k", "other-#{index}", 60) }

    assert_equal "first", store.get("k")
  end
end

class IdentityStoreConcurrencyTest < Minitest::Test
  include TestSupport
  include Kampe::TelegramTwoFactor

  def test_only_one_of_many_concurrent_transitions_applies
    identities = Stores::MemoryIdentities.new(YieldingClock.new)

    results = race(8) do |index|
      identities.transition("u", "chat-#{index}", nil, "gen-#{index}")
    end

    applied = results.compact

    assert_equal 1, applied.length,
                 "all started from the same expectation, so one may apply"

    # And the stored row is the winner's, not a mixture.
    stored = identities.find_by_user_id("u")

    assert_equal applied.first.chat_id, stored.chat_id
    assert_equal applied.first.generation, stored.generation
  end

  def test_one_chat_cannot_be_claimed_by_two_accounts_concurrently
    identities = Stores::MemoryIdentities.new(YieldingClock.new)

    results = race(8) do |index|
      identities.transition("user-#{index}", "shared", nil, "gen-#{index}")
      "won"
    rescue ChatAlreadyLinked
      "refused"
    end

    assert_equal 1, results.count("won"), "a chat belongs to one account"
  end
end

# The same properties, through a store whose critical sections are forced to
# interleave.
#
# The class below runs on a frozen clock, and that is not enough on its own: a
# store built from get-then-delete rather than an atomic take passes every test
# in it, because the gap between the two operations closes before another
# thread is scheduled. Removing the atomic take from the service was the one
# mutation the first version of this suite did not catch.
#
# Here every clock read sleeps, so the gap is held open and the race happens.
class ServiceOnYieldingStoreTest < HarnessTest
  def build_clock
    YieldingClock.new
  end

  def test_exactly_one_of_many_concurrent_verifications_succeeds
    seed
    tfa.push("user-1")
    code = last_code

    results = race(12) { tfa.verify("user-1", code) }

    assert_equal 1, results.count(&:ok?),
                 "a code read and then deleted, rather than taken, would be " \
                 "accepted by more than one caller"
  end

  def test_many_concurrent_challenges_send_one_code
    seed

    results = race(8) { tfa.push("user-1") }

    assert_equal 1, results.count(&:ok?)
    assert_equal 1, telegram.sent.length
  end

  def test_one_link_token_binds_one_chat
    request = tfa.start_deep_link("user-1")

    results = race(8) { |index| tfa.complete_deep_link(request.token, "chat-#{index}") }

    assert_equal 1, results.count(&:ok?)
  end
end

# Whether the service consumes a challenge in one store operation.
#
# Splitting it into a read and a delete is the oldest way to break single use,
# and it is invisible to every other test here: the two calls complete inside
# one scheduling slice, so the code still appears to be used once.
class AtomicConsumptionTest < HarnessTest
  def service_on(store)
    Service.new(
      config: config, store: store, identities: identities,
      telegram: telegram, messages: messages, clock: clock
    )
  end

  def test_a_verification_consumes_the_record_in_a_single_operation
    recorder = RecordingStore.new(store, 0)
    tfa = service_on(recorder)
    seed
    tfa.push("user-1")
    recorder.reset_calls

    assert tfa.verify("user-1", last_code).ok?

    # Anything longer is a read-modify-write with a gap in it.
    assert_equal [:take], recorder.calls,
                 "a get followed by a forget would let two verifications both win"
  end

  def test_only_one_verification_wins_when_the_store_yields_between_calls
    recorder = RecordingStore.new(store)
    tfa = service_on(recorder)
    seed
    tfa.push("user-1")
    code = last_code

    results = race(8) { tfa.verify("user-1", code) }

    assert_equal 1, results.count(&:ok?),
                 "with the gap between store calls held open, only an atomic " \
                 "take keeps a code single-use"
  end

  def test_only_one_challenge_is_issued_when_the_store_yields_between_calls
    recorder = RecordingStore.new(store)
    tfa = service_on(recorder)
    seed

    results = race(8) { tfa.push("user-1") }

    assert_equal 1, results.count(&:ok?), "the cooldown must be a reservation, not a check"
    assert_equal 1, telegram.sent.length
  end
end

class ServiceConcurrencyTest < HarnessTest
  # The properties an application actually depends on.
  def test_exactly_one_of_many_concurrent_verifications_succeeds
    seed
    tfa.push("user-1")
    code = last_code

    results = race(16) { tfa.verify("user-1", code) }

    assert_equal 1, results.count(&:ok?),
                 "a single-use code must authorise exactly one action"
  end

  # "Concurrent failures preserve the attempt budget" means no increment is
  # lost - not that sixteen parallel guesses spend sixteen attempts. With an
  # atomic take only the holder's guess is compared at all; the rest are told
  # expired without being evaluated, and a guess that is never evaluated cannot
  # be a hit.
  #
  # The property that must hold is that the number of guesses actually compared
  # never exceeds the budget, however many threads are thrown at it.
  def test_parallelism_cannot_win_more_guesses_than_the_budget
    seed
    tfa.push("user-1")
    wrong = wrong_code(last_code)

    results = race(16) { tfa.verify("user-1", wrong) }
    evaluated = results.count { |r| r.error == ErrorCode::INVALID }

    assert_operator evaluated, :>=, 1, "at least one guess must be checked"
    assert_operator evaluated, :<=, config.max_attempts,
                    "parallelism must not buy more comparisons than the budget allows"
  end

  def test_the_budget_still_ends_the_code_in_sequence
    seed
    tfa.push("user-1")
    code = last_code
    wrong = wrong_code(code)

    config.max_attempts.times { tfa.verify("user-1", wrong) }

    refute tfa.verify("user-1", code).ok?, "five wrong guesses must kill the code"
  end

  def test_many_concurrent_challenges_send_one_code
    seed

    results = race(8) { tfa.push("user-1") }

    assert_equal 1, results.count(&:ok?)
    assert_equal 1, telegram.sent.length
  end

  def test_one_link_token_binds_one_chat
    request = tfa.start_deep_link("user-1")

    results = race(8) { |index| tfa.complete_deep_link(request.token, "chat-#{index}") }

    assert_equal 1, results.count(&:ok?), "a link token must bind exactly one chat"
  end

  def test_concurrent_ordinary_links_cannot_replace_each_other
    tokens = Array.new(8) { tfa.start_deep_link("user-1").token }

    results = race(8) { |index| tfa.complete_deep_link(tokens[index], "chat-#{index}") }

    assert_equal 1, results.count(&:ok?)

    identity = tfa.identity("user-1")

    refute_nil identity
    assert_equal identity.user_id, tfa.identity_for_chat(identity.chat_id).user_id
  end
end
