# frozen_string_literal: true

require_relative "support"

# SPEC.md sections 4, 5 and 6 - challenge, verification, purpose.
class ChallengeTest < HarnessTest
  def test_push_sends_a_code_to_the_linked_chat
    seed

    result = tfa.push("user-1")

    assert result.ok?
    assert_equal 1, telegram.sent.length
    assert_equal "555000111", telegram.sent.first[:chat_id]
    assert_match(/\A\d{6}\z/, last_code)
  end

  def test_push_refuses_an_unlinked_account
    assert_equal ErrorCode::NOT_LINKED, tfa.push("nobody").error
    assert_empty telegram.sent
  end

  def test_an_unverified_link_is_not_a_second_factor
    # A chat id with no verification timestamp: a link started and never
    # finished.
    identities.transition("user-1", nil, nil, "gen-partial")

    assert_equal ErrorCode::NOT_LINKED, tfa.push("user-1").error
  end

  def test_the_code_never_appears_in_the_result
    seed

    result = tfa.push("user-1")

    # The result routinely goes straight into an HTTP response, so assert on
    # its serialised form rather than its fields.
    refute_includes result.to_h.to_s, last_code
  end

  def test_a_second_request_inside_the_cooldown_is_refused
    seed

    tfa.push("user-1")
    second = tfa.push("user-1")

    assert_equal ErrorCode::COOLDOWN, second.error
    assert_equal 120, second.retry_after(clock.now)
    assert_equal 1, telegram.sent.length
  end

  def test_a_request_after_the_cooldown_is_allowed
    seed

    tfa.push("user-1")
    clock.advance(121)

    assert tfa.push("user-1").ok?
    assert_equal 2, telegram.sent.length
  end

  def test_a_failed_delivery_leaves_no_live_code_and_no_cooldown
    seed
    telegram.should_fail_sending = true

    assert_equal ErrorCode::SEND_FAILED, tfa.push("user-1").error

    # A code the user never received must not occupy the slot, or the account
    # is stuck until the cooldown expires with no way to try again.
    telegram.should_fail_sending = false

    assert tfa.push("user-1").ok?
  end

  def test_a_late_delivery_failure_cannot_discard_a_newer_challenge
    seed

    telegram.fail_next_send do
      clock.advance(121)
      tfa.push("user-1", PURPOSE_LOGIN)
    end

    assert_equal ErrorCode::SEND_FAILED, tfa.push("user-1", PURPOSE_LOGIN).error

    assert tfa.verify("user-1", last_code, PURPOSE_LOGIN).ok?,
           "the cleanup for a failed send must only discard its own challenge"
  end

  def test_pull_issues_a_code_for_a_known_chat
    seed

    assert tfa.pull("555000111").ok?
    assert_match(/\A\d{6}\z/, last_code)
  end

  def test_pull_refuses_an_unknown_chat
    assert_equal ErrorCode::NOT_LINKED, tfa.pull("404404404").error
  end

  # The single-key rule of SPEC.md section 4. An implementation that writes one
  # key on push and reads another passes every pull-path test and silently
  # fails every real push.
  def test_a_pushed_and_a_pulled_code_verify_through_the_same_call
    seed

    tfa.push("user-1")

    assert tfa.verify("user-1", last_code).ok?

    clock.advance(121)
    tfa.pull("555000111")

    assert tfa.verify("user-1", last_code).ok?
  end

  def test_codes_are_stored_hashed_rather_than_in_plaintext
    seed

    tfa.push("user-1")
    record = store.get(config.key("code", "user-1"))

    assert_kind_of Hash, record
    refute_equal last_code, record["hash"]
    assert_equal 64, record["hash"].length
  end

  # The two accounts share a generation on purpose.
  #
  # With different ones the enrollment check in verify refuses the transplanted
  # record before the digest is ever compared, so the test would pass against a
  # hasher that ignored the account entirely - which it did, until a mutation
  # run removed the context binding and this test stayed green.
  def test_a_digest_does_not_verify_against_a_different_account
    identities.seed("user-1", "555000111", "shared-generation")
    identities.seed("user-2", "777000222", "shared-generation")

    tfa.push("user-1")
    code = last_code
    record = store.get(config.key("code", "user-1"))

    # Transplant it, as a store-level attacker holding a known code would.
    store.put(config.key("code", "user-2"), record, 300)

    refute tfa.verify("user-2", code).ok?,
           "the digest is keyed to the account, so only that account's code matches it"
    assert tfa.verify("user-1", code).ok?
  end
end

class VerificationTest < HarnessTest
  def test_the_right_code_passes
    seed
    tfa.push("user-1")

    assert tfa.verify("user-1", last_code).ok?
  end

  def test_a_wrong_code_fails_and_spends_an_attempt
    seed
    tfa.push("user-1")

    result = tfa.verify("user-1", wrong_code(last_code))

    assert_equal ErrorCode::INVALID, result.error
    assert_equal 4, result.attempts_remaining
  end

  def test_a_code_works_only_once
    seed
    tfa.push("user-1")
    code = last_code

    assert tfa.verify("user-1", code).ok?

    replay = tfa.verify("user-1", code)

    refute replay.ok?
    assert_equal ErrorCode::EXPIRED, replay.error
  end

  def test_the_attempt_budget_kills_the_code
    seed
    tfa.push("user-1")
    code = last_code
    wrong = wrong_code(code)

    4.times { assert_equal ErrorCode::INVALID, tfa.verify("user-1", wrong).error }

    assert_equal ErrorCode::TOO_MANY_ATTEMPTS, tfa.verify("user-1", wrong).error

    # And the real code is dead too: the budget belongs to the code, not to
    # the attacker.
    refute tfa.verify("user-1", code).ok?
  end

  def test_an_expired_code_fails
    seed
    tfa.push("user-1")
    code = last_code

    clock.advance(301)

    assert_equal ErrorCode::EXPIRED, tfa.verify("user-1", code).error
  end

  def test_a_wrong_guess_does_not_extend_the_codes_life
    seed
    tfa.push("user-1")
    code = last_code

    clock.advance(200)
    tfa.verify("user-1", wrong_code(code))

    clock.advance(101) # 301s since issue

    assert_equal ErrorCode::EXPIRED, tfa.verify("user-1", code).error
  end

  def test_whitespace_around_a_pasted_code_is_tolerated
    seed
    tfa.push("user-1")

    assert tfa.verify("user-1", " #{last_code}\n").ok?
  end

  def test_a_user_id_is_treated_as_an_opaque_string
    uuid = "9b7c2f0e-4d5a-4c21-8f3b-1a2b3c4d5e6f"
    identities.seed(uuid, "555000111", "gen-uuid")

    assert tfa.push(uuid).ok?
    assert tfa.verify(uuid, last_code).ok?
  end
end

class PurposeTest < HarnessTest
  def test_a_pushed_code_does_not_satisfy_another_purpose
    seed
    tfa.push("user-1", PURPOSE_LOGIN)

    refute tfa.verify("user-1", last_code, "withdrawal").ok?
  end

  def test_omitting_the_purpose_means_login_not_a_wildcard
    seed
    tfa.push("user-1", "withdrawal")

    refute tfa.verify("user-1", last_code).ok?
  end

  def test_an_on_demand_code_satisfies_any_purpose
    seed
    tfa.pull("555000111")

    assert tfa.verify("user-1", last_code, "withdrawal").ok?
  end

  def test_a_purpose_mismatch_reports_invalid_and_spends_an_attempt
    seed
    tfa.push("user-1", PURPOSE_LOGIN)
    code = last_code

    first = tfa.verify("user-1", code, "withdrawal")

    # Reporting the mismatch distinctly would tell a caller that a live code
    # exists for a different step, which it has not proved it may know.
    assert_equal ErrorCode::INVALID, first.error
    assert_equal 4, first.attempts_remaining
    assert_equal 3, tfa.verify("user-1", code, "withdrawal").attempts_remaining
  end

  def test_unlinking_rejects_a_code_pushed_for_a_login
    seed
    tfa.push("user-1", PURPOSE_LOGIN)

    refute tfa.unlink("user-1", last_code).ok?
    assert tfa.linked?("user-1")
  end

  def test_unlinking_accepts_a_code_the_user_fetched
    seed
    tfa.pull("555000111")

    assert tfa.unlink("user-1", last_code).ok?
    refute tfa.linked?("user-1")
  end

  def test_the_on_demand_exemption_can_be_narrowed
    narrowed = with_config(on_demand_satisfies: ["login"])
    seed

    narrowed.pull("555000111")

    assert narrowed.verify("user-1", last_code, "login").ok?

    clock.advance(121)
    narrowed.pull("555000111")

    refute narrowed.verify("user-1", last_code, "withdrawal").ok?
  end
end

# SPEC.md sections 2 and 3 - linking.
class LinkingTest < HarnessTest
  def test_the_deeplink_flow_links_the_account
    request = tfa.start_deep_link("user-1")

    assert_equal "https://t.me/kampe_test_bot?start=#{request.token}", request.url
    assert tfa.complete_deep_link(request.token, "555000111").ok?
    assert tfa.linked?("user-1")
  end

  def test_a_deeplink_token_is_single_use
    request = tfa.start_deep_link("user-1")
    tfa.complete_deep_link(request.token, "555000111")

    # A second presentation from a different chat: the obvious attack if the
    # token survives, since the token travels through a chat message.
    replay = tfa.complete_deep_link(request.token, "999999999")

    assert_equal ErrorCode::INVALID_TOKEN, replay.error
  end

  def test_an_expired_deeplink_token_is_refused
    request = tfa.start_deep_link("user-1")
    clock.advance(601)

    assert_equal ErrorCode::INVALID_TOKEN,
                 tfa.complete_deep_link(request.token, "555000111").error
  end

  def test_the_link_token_is_not_stored_in_plaintext
    request = tfa.start_deep_link("user-1")

    assert_nil store.get(config.key("link", request.token))
    assert tfa.complete_deep_link(request.token, "555000111").ok?
  end

  def test_the_paste_flow_links_the_account
    request = tfa.start_paste_link("555000111")

    # The paste flow's key is derived from the code, so all outstanding codes
    # share one namespace. Eight base32 characters is 40 bits.
    assert_equal 8, request.token.length
    assert_match(/\A[#{LINK_ALPHABET}]{8}\z/, request.token)

    assert tfa.complete_paste_link("user-1", request.token).ok?
    assert tfa.linked?("user-1")
  end

  def test_a_paste_code_is_accepted_in_lower_case
    request = tfa.start_paste_link("555000111")

    assert tfa.complete_paste_link("user-1", request.token.downcase).ok?
  end

  # One Telegram account as the factor for several accounts means one
  # compromised Telegram account compromises all of them.
  def test_a_chat_cannot_become_the_factor_for_a_second_account
    first = tfa.start_deep_link("user-1")
    tfa.complete_deep_link(first.token, "555000111")

    second = tfa.start_deep_link("user-2")

    assert_equal ErrorCode::ALREADY_LINKED,
                 tfa.complete_deep_link(second.token, "555000111").error
    refute tfa.linked?("user-2")
    assert_equal "user-1", tfa.identity_for_chat("555000111").user_id
  end

  def test_an_account_cannot_be_moved_without_a_replacement
    first = tfa.start_deep_link("user-1")
    tfa.complete_deep_link(first.token, "555000111")

    second = tfa.start_deep_link("user-1")

    assert_equal ErrorCode::ALREADY_LINKED,
                 tfa.complete_deep_link(second.token, "777000222").error
    assert_equal "555000111", tfa.identity("user-1").chat_id
  end

  def test_relinking_the_same_chat_is_idempotent
    first = tfa.start_deep_link("user-1")
    tfa.complete_deep_link(first.token, "555000111")

    # A user who taps the same link twice, or whose first confirmation was
    # lost, should see success rather than a conflict.
    second = tfa.start_deep_link("user-1")

    assert tfa.complete_deep_link(second.token, "555000111").ok?
  end
end
