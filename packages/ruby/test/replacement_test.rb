# frozen_string_literal: true

require_relative "support"

# SPEC.md 3.3 - moving the factor to a different Telegram account.
class ReplacementTest < HarnessTest
  def test_a_proven_replacement_moves_the_factor
    seed
    tfa.push("user-1", PURPOSE_REPLACE)

    request = tfa.start_chat_replacement("user-1", last_code)

    assert_kind_of LinkRequest, request
    assert tfa.complete_deep_link(request.token, "777000222").ok?
    assert_equal "777000222", tfa.identity("user-1").chat_id
    assert_nil tfa.identity_for_chat("555000111")
  end

  # The mark that authorises rebinding lives on the stored token. If it were
  # taken from the resolving call instead, the proof step could be skipped by
  # presenting an ordinary link token.
  def test_an_ordinary_token_cannot_move_a_verified_binding
    seed

    ordinary = tfa.start_deep_link("user-1")

    assert_equal ErrorCode::ALREADY_LINKED,
                 tfa.complete_deep_link(ordinary.token, "777000222").error
    assert_equal "555000111", tfa.identity("user-1").chat_id
  end

  # A refused replacement must not cost the user the factor they already had.
  # Releasing the old binding before checking the destination made a failed
  # request strip the account of its second factor - which is what happened in
  # an earlier revision of the PHP and Node packages.
  def test_a_refused_replacement_leaves_the_original_factor_intact
    seed("user-1", "555000111")
    seed("user-2", "777000222")
    tfa.push("user-1", PURPOSE_REPLACE)

    request = tfa.start_chat_replacement("user-1", last_code)

    assert_kind_of LinkRequest, request
    assert_equal ErrorCode::ALREADY_LINKED,
                 tfa.complete_deep_link(request.token, "777000222").error

    # The other account keeps its chat...
    assert_equal "user-2", tfa.identity_for_chat("777000222").user_id
    # ...and so does this one.
    assert_equal "555000111", tfa.identity("user-1").chat_id
  end

  def test_a_refused_replacement_does_not_announce_one
    seed("user-1", "555000111")
    seed("user-2", "777000222")
    tfa.push("user-1", PURPOSE_REPLACE)

    request = tfa.start_chat_replacement("user-1", last_code)

    assert_kind_of LinkRequest, request
    telegram.reset

    tfa.complete_deep_link(request.token, "777000222")

    # Telling the user their factor was removed when it was not is its own
    # small incident: they will go looking for an attacker.
    assert_empty telegram.sent
  end

  # Authority over a factor must not survive the factor.
  def test_a_replacement_token_is_void_after_recovery
    seed
    tfa.push("user-1", PURPOSE_REPLACE)

    stale = tfa.start_chat_replacement("user-1", last_code)

    assert_kind_of LinkRequest, stale

    # The user loses their Telegram account and support recovers them.
    tfa.unlink_after_external_proof("user-1", "verified out of band")
    fresh = tfa.start_deep_link("user-1")
    tfa.complete_deep_link(fresh.token, "888000333")

    assert_equal ErrorCode::INVALID_TOKEN,
                 tfa.complete_deep_link(stale.token, "999000444").error
    assert_equal "888000333", tfa.identity("user-1").chat_id
  end

  # What a timestamp fingerprint could not express: chat_id|linked_at repeats
  # when the same chat is unlinked and relinked inside one second, reviving
  # every token minted beforehand. The clock never advances here.
  def test_unlink_and_relink_within_one_second_invalidates_old_tokens
    seed
    tfa.push("user-1", PURPOSE_REPLACE)

    stale = tfa.start_chat_replacement("user-1", last_code)

    assert_kind_of LinkRequest, stale

    before = clock.now

    tfa.unlink_after_external_proof("user-1", "user asked")
    fresh = tfa.start_deep_link("user-1")
    tfa.complete_deep_link(fresh.token, "555000111")

    assert_equal before, clock.now, "the whole sequence is one second"
    refute tfa.complete_deep_link(stale.token, "999000444").ok?
    assert_equal "555000111", tfa.identity("user-1").chat_id
  end

  # The window between the code being accepted and the token being written.
  #
  # An implementation that re-reads the enrollment after verifying and records
  # *that* generation hands the token authority over whatever it finds - which,
  # if a recovery landed in that window, is the recovered enrollment the user
  # never proved.
  def test_recovery_between_the_code_and_the_token_refuses_authorisation
    seed("victim")
    tfa.push("victim", PURPOSE_REPLACE)
    code = last_code

    # Fire the recovery on the identity read that happens after verify.
    reads = 0
    original = identities.method(:find_by_user_id)

    identities.define_singleton_method(:find_by_user_id) do |user_id|
      reads += 1

      if reads == 3
        TestHooks.recover_victim
      end

      original.call(user_id)
    end

    TestHooks.service = tfa
    request = tfa.start_chat_replacement("victim", code)

    identities.singleton_class.remove_method(:find_by_user_id)

    # Either refused outright, or the token it produced is inert. Silently
    # acquiring authority over the recovered enrollment is neither.
    if request.is_a?(LinkRequest)
      refute tfa.complete_deep_link(request.token, "999000444").ok?,
             "a token minted after recovery must not bind"
    end

    assert_equal "888000333", tfa.identity("victim").chat_id,
                 "the recovered enrollment must survive"
  end

  # Preventing a stale record from being written back is best-effort; accepting
  # one is impossible. So put it back by hand - exactly what a lost race would
  # do - and require that it still cannot authorise anything.
  def test_a_stale_record_is_inert_even_when_written_back
    seed
    tfa.push("user-1")
    code = last_code

    key = config.key("code", "user-1")
    record = store.get(key)

    tfa.unlink_after_external_proof("user-1", "support recovery")
    fresh = tfa.start_deep_link("user-1")
    tfa.complete_deep_link(fresh.token, "888000333")

    # Resurrect it.
    store.put(key, record, 300)

    refute tfa.verify("user-1", code).ok?,
           "a record from a superseded enrollment must be inert even if restored"
  end

  def test_replacement_invalidates_a_code_sent_to_the_old_chat
    seed
    tfa.push("user-1", PURPOSE_REPLACE)

    request = tfa.start_chat_replacement("user-1", last_code)

    assert_kind_of LinkRequest, request

    clock.advance(121)
    tfa.push("user-1", PURPOSE_LOGIN)
    in_flight = last_code

    assert tfa.complete_deep_link(request.token, "777000222").ok?
    refute tfa.verify("user-1", in_flight, PURPOSE_LOGIN).ok?
  end

  def test_a_login_code_cannot_authorise_a_replacement
    seed
    tfa.push("user-1", PURPOSE_LOGIN)

    result = tfa.start_chat_replacement("user-1", last_code)

    assert_kind_of VerificationResult, result
    refute result.ok?
  end

  def test_the_generation_survives_unlinking
    seed

    tfa.unlink_after_external_proof("user-1", "user asked")

    identity = tfa.identity("user-1")

    # The row remains, carrying a new generation and no chat: revocation has to
    # outlive the binding it revoked.
    refute_nil identity
    assert_nil identity.chat_id
    refute identity.verified?
    refute_equal "gen-user-1", identity.generation
  end

  def test_unlinking_notifies_the_chat_and_clears_pending
    seed
    tfa.push("user-1", PURPOSE_UNLINK)
    code = last_code
    telegram.reset

    assert tfa.unlink("user-1", code).ok?
    assert_equal 1, telegram.sent.length
    assert_includes telegram.last_message.downcase, "unlinked"
    assert_nil store.get(config.key("code", "user-1"))
    assert_nil store.get(config.key("cooldown", "user-1"))
  end
end

# Shared state for the singleton-method hook above, which cannot close over
# test locals.
module TestHooks
  class << self
    attr_accessor :service

    def recover_victim
      service.unlink_after_external_proof("victim", "support recovery")
      fresh = service.start_deep_link("victim")
      service.complete_deep_link(fresh.token, "888000333")
    end
  end
end
