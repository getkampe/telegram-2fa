# frozen_string_literal: true

require "json"
require_relative "support"

# A Redis stand-in: enough of the protocol for the store, and nothing more.
#
# Its own semantics are the point of the exercise - SET NX refusing, GETDEL
# returning and removing in one call - so the store is checked against the
# behaviour the real server has rather than against a mock of itself.
class FakeRedis
  attr_reader :calls

  def initialize
    @items = {}
    @calls = []
  end

  def get(key)
    @calls << [:get, key]
    @items[key]
  end

  def set(key, value, ex: nil, nx: false)
    @calls << [:set, key, ex, nx]

    return nil if nx && @items.key?(key)

    @items[key] = value
    "OK"
  end

  def del(key)
    @calls << [:del, key]
    @items.delete(key) ? 1 : 0
  end

  def getdel(key)
    @calls << [:getdel, key]
    @items.delete(key)
  end

  def raw(key) = @items[key]
  def keys = @items.keys
end

# Older than Redis 6.2: no GETDEL, so the store must fall back to a script.
class ScriptOnlyRedis < FakeRedis
  undef_method :getdel

  def eval(script, keys: [], argv: [])
    @calls << [:eval, keys.first, argv]

    raise "unexpected script" unless script.include?("GET") && script.include?("DEL")

    @items.delete(keys.first)
  end
end

class NoAtomicPrimitiveRedis < FakeRedis
  undef_method :getdel
end

# redis-rb converts the server's null reply to +false+ rather than passing nil
# through, so a refused SET NX arrives as a boolean. Any store that checks only
# for nil reads that as a win.
class BoolifyingRedis < FakeRedis
  def set(key, value, ex: nil, nx: false)
    result = super

    result.nil? ? false : true
  end
end

class RedisStoreTest < Minitest::Test
  include TestSupport
  include Kampe::TelegramTwoFactor

  def setup
    super

    @redis = FakeRedis.new
    @store = Stores::Redis.new(@redis)
  end

  def test_a_record_round_trips_as_json
    @store.put("k", { "hash" => "abc", "attempts" => 0 }, 300)

    assert_equal({ "hash" => "abc", "attempts" => 0 }, @store.get("k"))
    assert_equal '{"hash":"abc","attempts":0}', @redis.raw("k")
  end

  def test_the_ttl_is_passed_to_the_server
    @store.put("k", { "a" => 1 }, 300)

    assert_includes @redis.calls, [:set, "k", 300, false]
  end

  def test_a_bare_integer_round_trips
    @store.put("cooldown", 1_700_000_120, 120)

    # The cooldown record is a number, not an object - SPEC.md section 9.
    assert_equal 1_700_000_120, @store.get("cooldown")
  end

  def test_a_missing_key_reads_as_nil
    assert_nil @store.get("absent")
  end

  def test_take_removes_the_key_and_returns_the_value
    @store.put("k", { "a" => 1 }, 300)

    assert_equal({ "a" => 1 }, @store.take("k"))
    assert_nil @store.get("k")
  end

  # The one property the whole single-use guarantee rests on: the value leaves
  # the server in the same operation that returns it.
  def test_take_is_one_server_operation
    @store.put("k", { "a" => 1 }, 300)
    @redis.calls.clear

    @store.take("k")

    assert_equal [[:getdel, "k"]], @redis.calls,
                 "a GET followed by a DEL would let two verifications both win"
  end

  def test_take_of_a_missing_key_is_nil
    assert_nil @store.take("absent")
  end

  def test_add_reserves_an_absent_key
    assert @store.add("k", "first", 60)
    assert_equal "first", @store.get("k")
  end

  def test_add_refuses_an_occupied_key_and_leaves_it_alone
    @store.add("k", "first", 60)

    refute @store.add("k", "second", 60)
    assert_equal "first", @store.get("k"), "the loser must not overwrite the winner"
  end

  def test_add_uses_set_nx
    @store.add("k", "first", 60)

    assert_includes @redis.calls, [:set, "k", 60, true],
                    "a read followed by a write would be a check-then-write race"
  end

  # The cooldown and the webhook's idempotency claim are both built on this
  # boolean, so misreading a refusal as a win means no cooldown at all and
  # updates processed twice.
  def test_a_refusal_reported_as_false_is_still_a_refusal
    store = Stores::Redis.new(BoolifyingRedis.new)

    assert store.add("k", "first", 60)
    refute store.add("k", "second", 60), "false is a refusal, not a win"
    assert_equal "first", store.get("k")
  end

  def test_forget_removes_the_key
    @store.put("k", "v", 60)
    @store.forget("k")

    assert_empty @redis.keys
  end

  # A key holding something this library did not write - a collision with
  # another application's prefix - must not raise from inside verification.
  def test_a_non_json_value_reads_as_absent
    @redis.set("k", "not json at all")

    assert_nil @store.get("k")
  end

  def test_a_client_without_getdel_falls_back_to_a_script
    redis = ScriptOnlyRedis.new
    store = Stores::Redis.new(redis)
    store.put("k", { "a" => 1 }, 300)

    assert_equal({ "a" => 1 }, store.take("k"))
    assert_nil store.get("k")
    assert_includes redis.calls.map(&:first), :eval
  end

  # Failing at construction is the whole point: a client that can only GET then
  # DEL would accept one code twice under load, and it would do so silently.
  def test_a_client_with_no_atomic_primitive_is_refused_at_construction
    error = assert_raises(ConfigurationError) do
      Stores::Redis.new(NoAtomicPrimitiveRedis.new)
    end

    assert_match(/one operation/, error.message)
  end
end

# The store is only useful if the service works through it, so run the protocol
# over it rather than asserting on keys.
class ServiceOnRedisTest < Minitest::Test
  include TestSupport
  include Kampe::TelegramTwoFactor

  def setup
    super

    @clock = FrozenClock.new
    @redis = FakeRedis.new
    @telegram = FakeTelegram.new
    @config = make_config
    @identities = Stores::MemoryIdentities.new(@clock)

    @tfa = Service.new(
      config: @config, store: Stores::Redis.new(@redis), identities: @identities,
      telegram: @telegram, messages: DefaultMessages.new, clock: @clock
    )

    @identities.seed("user-1", "555000111", "gen-user-1")
  end

  def code
    TestSupport::CODE_PATTERN.match(@telegram.last_message)&.captures&.first.to_s
  end

  def test_a_code_is_issued_and_verified_through_the_redis_store
    assert @tfa.push("user-1").ok?
    assert @tfa.verify("user-1", code).ok?
  end

  def test_a_code_is_single_use_through_the_redis_store
    @tfa.push("user-1")
    issued = code

    assert @tfa.verify("user-1", issued).ok?
    assert_equal ErrorCode::EXPIRED, @tfa.verify("user-1", issued).error
  end

  def test_the_attempt_counter_survives_the_json_round_trip
    @tfa.push("user-1")
    wrong = code == "000000" ? "111111" : "000000"

    assert_equal 4, @tfa.verify("user-1", wrong).attempts_remaining
    assert_equal 3, @tfa.verify("user-1", wrong).attempts_remaining
  end

  def test_the_cooldown_works_through_the_redis_store
    @tfa.push("user-1")

    assert_equal ErrorCode::COOLDOWN, @tfa.push("user-1").error
  end

  def test_the_deeplink_flow_works_through_the_redis_store
    request = @tfa.start_deep_link("user-2")

    assert @tfa.complete_deep_link(request.token, "777000222").ok?
    assert_equal ErrorCode::INVALID_TOKEN,
                 @tfa.complete_deep_link(request.token, "888000333").error
  end
end
