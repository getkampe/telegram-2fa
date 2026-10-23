# frozen_string_literal: true

require "json"
require_relative "support"

# SPEC.md section 9, against the shared fixture in /conformance.
#
# The repository claims the implementations can share one bot and one store.
# That is a claim about field names and hash construction, and it only means
# anything if every implementation reads the same committed records.
class ConformanceTest < Minitest::Test
  include TestSupport
  include Kampe::TelegramTwoFactor

  FIXTURE = JSON.parse(
    File.read(File.expand_path("../../../conformance/records.json", __dir__))
  )

  def setup
    super

    @clock = FrozenClock.new(FIXTURE["now"])
    @store = Stores::Memory.new(@clock)
    @identities = Stores::MemoryIdentities.new(@clock)
    @config = make_config(
      key_prefix: FIXTURE["config"]["key_prefix"],
      hash_algorithm: FIXTURE["config"]["hash_algorithm"],
      hash_pepper: FIXTURE["config"]["hash_pepper"]
    )
    @tfa = Service.new(
      config: @config, store: @store, identities: @identities,
      telegram: FakeTelegram.new, messages: DefaultMessages.new, clock: @clock
    )
  end

  def test_a_challenge_record_written_elsewhere_verifies_here
    record = FIXTURE["code_record"]

    # Seed the exact enrollment the fixture's challenge belongs to: a challenge
    # from a superseded enrollment is refused, so interop depends on agreeing
    # about that field too.
    @identities.seed(record["user_id"], "555000111", record["enrollment"])
    @store.put(record["key"], record["value"], 300)

    assert @tfa.verify(record["user_id"], record["plaintext_code"], "withdrawal").ok?,
           "a record in the shared wire format must verify through the public API"
  end

  def test_a_challenge_record_written_here_matches_the_wire_format
    @identities.seed("user-1", "555000111", "gen-local")
    @tfa.push("user-1", "withdrawal")

    written = @store.get(FIXTURE["code_record"]["key"])

    assert_equal FIXTURE["code_record"]["value"].keys.sort, written.keys.sort,
                 "field names are the wire format of SPEC.md section 9"
  end

  def test_an_on_demand_record_from_elsewhere_is_general_purpose
    record = FIXTURE["on_demand_record"]
    @identities.seed(record["user_id"], "777000222", record["enrollment"])
    @store.put(record["key"], record["value"], 300)

    assert @tfa.verify(record["user_id"], record["plaintext_code"], "login").ok?
  end

  def test_a_deeplink_record_written_elsewhere_resolves_here
    record = FIXTURE["deeplink_record"]
    @store.put(record["key"], record["value"], 600)

    assert @tfa.complete_deep_link(record["token"], "888000333").ok?
    assert_equal "888000333", @tfa.identity(record["user_id"]).chat_id
  end

  def test_a_paste_record_written_elsewhere_resolves_here
    record = FIXTURE["paste_record"]
    @store.put(record["key"], record["value"], 600)

    assert @tfa.complete_paste_link("user-9", record["token"]).ok?
    assert_equal record["chat_id"], @tfa.identity("user-9").chat_id
  end

  def test_the_cooldown_record_is_a_bare_integer
    @identities.seed("user-1", "555000111", "gen-local")
    @tfa.push("user-1")

    written = @store.get(FIXTURE["cooldown_record"]["key"])

    # Not an object: the other implementations read this as a number.
    assert_kind_of Integer, written
    assert_equal FIXTURE["cooldown_record"]["value"], written
  end

  # A store may hand back a numeric string rather than an integer. Laravel's
  # Redis cache does exactly that, because it leaves bare numerics unserialised
  # so INCR still works on them.
  def test_a_cooldown_returned_as_a_string_is_still_understood
    @identities.seed("user-1", "555000111", "gen-local")
    @tfa.push("user-1")

    key = @config.key("cooldown", "user-1")
    @store.put(key, @store.get(key).to_s, 120)

    result = @tfa.push("user-1")

    assert_equal ErrorCode::COOLDOWN, result.error
    assert_kind_of Integer, result.next_send_at
  end
end
