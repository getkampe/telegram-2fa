# frozen_string_literal: true

require_relative "support"

SECRET = ("s" * 48).freeze

# SPEC.md section 7. The check that matters most: without it the webhook
# accepts a forged assertion that any chat id is asking for a code.
class VerifierTest < Minitest::Test
  include TestSupport
  include Kampe::TelegramTwoFactor

  def test_the_matching_secret_is_accepted
    assert Webhook::Verifier.new(make_config).accepts?(SECRET)
  end

  def test_a_wrong_or_missing_secret_is_rejected
    verifier = Webhook::Verifier.new(make_config)

    ["", nil, "x" * 48].each do |value|
      refute verifier.accepts?(value), "#{value.inspect} must be rejected"
    end
  end

  # Truncating or length-insensitive comparisons are the classic way this gets
  # written wrong.
  def test_a_prefix_or_extension_of_the_secret_is_rejected
    verifier = Webhook::Verifier.new(make_config)

    refute verifier.accepts?("s" * 47)
    refute verifier.accepts?("s" * 49)
  end

  def test_ip_restriction_accepts_telegram_ranges
    verifier = Webhook::Verifier.new(make_config(restrict_webhook_ips: true))

    ["149.154.160.1", "149.154.175.254", "91.108.4.10"].each do |address|
      assert verifier.accepts?(SECRET, address), address
    end
  end

  def test_ip_restriction_rejects_everything_else
    verifier = Webhook::Verifier.new(make_config(restrict_webhook_ips: true))

    ["8.8.8.8", "149.154.176.1", "127.0.0.1", nil, "not-an-ip"].each do |address|
      refute verifier.accepts?(SECRET, address), address.inspect
    end
  end

  # Off by default because behind a proxy the peer address is the proxy, so
  # the check would be either useless or actively misleading.
  def test_ip_restriction_is_off_by_default
    assert Webhook::Verifier.new(make_config).accepts?(SECRET, "8.8.8.8")
  end
end

class ConfigValidationTest < Minitest::Test
  include TestSupport
  include Kampe::TelegramTwoFactor

  def test_a_missing_or_short_webhook_secret_is_refused
    ["", "x"].each do |secret|
      assert_raises(ConfigurationError) { make_config(webhook_secret: secret) }
    end
  end

  def test_a_missing_or_short_pepper_is_refused
    ["", "too-short"].each do |pepper|
      assert_raises(ConfigurationError) { make_config(hash_pepper: pepper) }
    end
  end

  def test_a_malformed_bot_token_is_refused
    assert_raises(ConfigurationError) { make_config(bot_token: "not-a-token") }
  end

  def test_a_bot_username_with_an_at_sign_is_refused
    assert_raises(ConfigurationError) { make_config(bot_username: "@kampe_test_bot") }
  end

  def test_out_of_range_numbers_are_refused
    [
      { max_attempts: 0 }, { max_attempts: 1000 }, { code_ttl: 86_400 },
      { cooldown: 0 }, { link_code_length: 6 }, { code_length: 4 }
    ].each do |overrides|
      assert_raises(ConfigurationError, overrides.inspect) { make_config(**overrides) }
    end
  end

  # A float reaches Redis as an EX argument.
  def test_non_integers_are_refused
    [{ code_ttl: 300.5 }, { max_attempts: 2.5 }, { code_ttl: "300" }].each do |overrides|
      assert_raises(ConfigurationError, overrides.inspect) { make_config(**overrides) }
    end
  end

  def test_an_empty_on_demand_allowlist_is_refused
    assert_raises(ConfigurationError) { make_config(on_demand_satisfies: []) }
  end

  # "5 attempts".to_i is 5 and "nonsense".to_i is 0, so to_i turns a typo into
  # a silently wrong security parameter. Integer() raises instead.
  def test_from_env_rejects_a_non_numeric_value
    env = {
      "TELEGRAM_BOT_TOKEN" => "123456789:AAFakeTokenForTestsOnly_0123456789abc",
      "TELEGRAM_WEBHOOK_SECRET" => SECRET,
      "TELEGRAM_2FA_HASH_PEPPER" => "p" * 48,
      "TELEGRAM_2FA_MAX_ATTEMPTS" => "5 attempts"
    }

    assert_raises(ConfigurationError) { Config.from_env(env) }
  end
end

class HandlerTest < HarnessTest
  def setup
    super

    @handler = Webhook::Handler.new(
      service: tfa, config: config, store: store,
      telegram: telegram, messages: messages, clock: clock
    )
    @next_update = 1000
  end

  attr_reader :handler

  # Not named +message+: Minitest::Assertions has a method of that name which
  # +refute+ calls with no arguments, so shadowing it breaks every refutation
  # in the class.
  def update_for(text, chat_id = "555000111")
    @next_update += 1

    {
      "update_id" => @next_update,
      "message" => {
        "message_id" => 1, "text" => text,
        "chat" => { "id" => chat_id, "type" => "private" }
      }
    }
  end

  def test_start_with_a_payload_links_the_account
    request = tfa.start_deep_link("user-1")

    handler.handle(update_for("/start #{request.token}"))

    assert tfa.linked?("user-1")
    assert_includes telegram.last_message, "second factor"
  end

  def test_code_issues_a_code_for_a_linked_chat
    seed
    handler.handle(update_for("/code"))

    assert_match(/\A\d{6}\z/, last_code)
  end

  def test_code_tells_an_unlinked_chat_how_to_link
    handler.handle(update_for("/code"))

    assert_includes telegram.last_message, "not linked"
  end

  def test_code_inside_the_cooldown_explains_the_wait
    seed
    handler.handle(update_for("/code"))
    handler.handle(update_for("/code"))

    assert_includes telegram.last_message, "just sent"
  end

  def test_a_repeated_update_id_is_dropped
    seed
    update = update_for("/code")

    assert handler.handle(update)
    refute handler.handle(update)
    assert_equal 1, telegram.sent.length
  end

  # An update marked done before its work succeeds is an update permanently
  # lost: the retry arrives, sees the marker, and drops it.
  def test_the_claim_is_released_when_handling_fails
    seed
    handler.on("boom") { raise "downstream failure" }
    update = update_for("/boom")

    assert_raises(RuntimeError) { handler.handle(update) }

    retried = false
    handler.on("boom") { retried = true }
    handler.handle(update)

    assert retried, "Telegram's retry must be processed"
  end

  # Otherwise the bot hands out verification codes in front of every member.
  def test_group_chats_are_ignored
    seed("user-1", "-1001234567890")
    update = update_for("/code", "-1001234567890")
    update["message"]["chat"]["type"] = "supergroup"

    handler.handle(update)

    assert_empty telegram.sent
  end

  # Codes travel application-to-user, never user-to-bot.
  def test_free_text_is_not_treated_as_a_code
    seed
    handler.handle(update_for("123456"))

    assert_includes telegram.last_message, "do not know that command"
  end

  def test_a_command_addressed_to_the_bot_is_understood
    seed
    handler.handle(update_for("/code@kampe_test_bot"))

    assert_match(/\A\d{6}\z/, last_code)
  end

  # Whoever holds the phone can already read the codes; letting them also
  # remove the factor turns a stolen phone into a single-factor account.
  def test_unlink_answers_with_instructions_and_does_not_unlink
    seed
    handler.handle(update_for("/unlink"))

    assert_includes telegram.last_message, "cannot be done from the chat"
    assert tfa.linked?("user-1")
  end

  def test_an_application_command_can_be_registered
    seen = nil
    handler.on("balance") { |chat_id, argument| seen = [chat_id, argument] }

    handler.handle(update_for("/balance usd"))

    assert_equal ["555000111", "usd"], seen
  end

  def test_a_callback_query_is_acknowledged_then_handled
    seed

    handler.handle({
                     "update_id" => 991,
                     "callback_query" => {
                       "id" => "cb-1", "data" => "code",
                       "message" => { "chat" => { "id" => "555000111", "type" => "private" } }
                     }
                   })

    assert_equal ["cb-1"], telegram.answered
    assert_match(/\A\d{6}\z/, last_code)
  end

  def test_an_update_with_no_message_is_ignored
    refute handler.handle({ "update_id" => 1 })
    assert_empty telegram.sent
  end
end
