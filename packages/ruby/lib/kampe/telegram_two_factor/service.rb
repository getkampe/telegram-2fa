# frozen_string_literal: true

require "openssl"

module Kampe
  module TelegramTwoFactor
    # Purposes name the step a code authorises.
    #
    # The default, for an ordinary sign-in.
    PURPOSE_LOGIN = "login"
    # The purpose of a code the user fetched themselves with /code.
    #
    # Such a code carries no knowledge of what it is about to authorise, so it
    # satisfies any requested purpose. That is sound because the user asked for
    # it deliberately - nothing the application did caused it to exist.
    PURPOSE_ON_DEMAND = "on_demand"
    # Proving the current factor before rebinding to a new chat.
    PURPOSE_REPLACE = "replace"
    # Proving the current factor before removing it.
    PURPOSE_UNLINK = "unlink"

    # Telegram as a second authentication factor.
    #
    # The whole protocol with no framework underneath it: linking (three
    # flows), challenge (two directions), verification, unlinking. Everything it
    # touches arrives through a duck-typed collaborator, so the same class runs
    # on Redis and Postgres or on hashes in a test.
    #
    # See SPEC.md for the normative protocol this implements.
    class Service
      def initialize(config:, store:, identities:, telegram:, messages:,
                     clock: nil, logger: nil, codes: nil, hasher: nil)
        @config = config
        @store = store
        @identities = identities
        @telegram = telegram
        @messages = messages
        @clock = clock || SystemClock.new
        @logger = logger || NullLogger.new
        @codes = codes || CodeGenerator.new
        @hasher = hasher || CodeHasher.new(config.hash_algorithm, config.hash_pepper)
      end

      attr_reader :config

      # ------------------------------------------------------------ identity

      # Whether this account has a proven Telegram second factor.
      def linked?(user_id)
        TelegramTwoFactor.verified?(@identities.find_by_user_id(user_id))
      end

      def identity(user_id)
        @identities.find_by_user_id(user_id)
      end

      # The enrollment behind a chat, for the webhook side of the protocol.
      def identity_for_chat(chat_id)
        @identities.find_by_chat_id(chat_id)
      end

      # ------------------------------------------------------------- linking

      # Begin the deeplink flow: mint a nonce bound to this account.
      #
      # Hand the returned url to the user as a button, or as a QR code when
      # they are on a desktop with Telegram on their phone. The token is bound
      # to the account before it ever reaches Telegram, which is what makes
      # this flow preferable to the paste flow: there is no window in which a
      # token is valid for whoever happens to present it.
      #
      # Minting is harmless for an already-linked account, so this does not
      # check; the check happens in complete_deep_link.
      def start_deep_link(user_id)
        token = @codes.deep_link_token
        expires_at = @clock.now + @config.link_ttl

        @store.put(
          @config.key("link", @hasher.hash(token)),
          { "user_id" => user_id, "expires_at" => expires_at },
          @config.link_ttl
        )

        @logger.info("telegram-2fa: deeplink issued", { user_id: user_id })

        LinkRequest.new(token: token, expires_at: expires_at,
                        url: @config.deep_link_url(token))
      end

      # Finish the deeplink flow, from the /start payload in a webhook update.
      def complete_deep_link(token, chat_id)
        # Single use, and taken atomically: a token read now and deleted later
        # can be resolved twice by two concurrent /start messages, and a token
        # that survives a failed attempt can be retried by anyone who saw it -
        # and it travelled through a chat, so others may have.
        record = @store.take(@config.key("link", @hasher.hash(token)))

        unless record.is_a?(Hash) && !record["user_id"].to_s.empty?
          @logger.warn("telegram-2fa: deeplink token not resolvable", { chat_id: chat_id })

          return LinkResult.failed(ErrorCode::INVALID_TOKEN)
        end

        return LinkResult.failed(ErrorCode::INVALID_TOKEN) if record["expires_at"].to_i < @clock.now

        replace = record["replace"] == true
        proven = record["generation"]
        proven = nil unless proven.is_a?(String)
        user_id = record["user_id"].to_s

        # A replacement token carries authority over an existing enrollment, so
        # it is only valid against the one whose possession was proved. If that
        # enrollment has since changed - recovered through support, unlinked,
        # or already replaced - the proof no longer refers to anything.
        if replace && !generation_current?(user_id, proven)
          @logger.warn("telegram-2fa: stale replacement token rejected", { user_id: user_id })

          return LinkResult.failed(ErrorCode::INVALID_TOKEN)
        end

        bind(user_id, chat_id, replace: replace, proven_generation: proven)
      end

      # Begin the paste flow, from the bot side: mint a code bound to this chat.
      def start_paste_link(chat_id)
        code = @codes.link_code(@config.link_code_length)
        expires_at = @clock.now + @config.link_ttl

        @store.put(
          @config.key("link", @hasher.hash(code)),
          { "chat_id" => chat_id, "expires_at" => expires_at },
          @config.link_ttl
        )

        @logger.info("telegram-2fa: paste link code issued")

        LinkRequest.new(token: code, expires_at: expires_at, url: nil)
      end

      # Finish the paste flow, from an authenticated page in your application.
      #
      # Two things this cannot check are the caller's: that user_id comes from
      # the session rather than the request body, and that the endpoint is
      # rate-limited. Without the rate limit the attempt budget on this flow is
      # unbounded, and link codes share one namespace across all users.
      def complete_paste_link(user_id, code)
        normalised = code.to_s.strip.upcase
        record = @store.take(@config.key("link", @hasher.hash(normalised)))

        unless record.is_a?(Hash) && !record["chat_id"].to_s.empty?
          @logger.warn("telegram-2fa: paste code not resolvable", { user_id: user_id })

          return LinkResult.failed(ErrorCode::INVALID_TOKEN)
        end

        return LinkResult.failed(ErrorCode::INVALID_TOKEN) if record["expires_at"].to_i < @clock.now

        bind(user_id, record["chat_id"].to_s)
      end

      # Begin moving the factor to a different Telegram account.
      #
      # Linking never silently moves a verified enrollment, because a flow that
      # did would let anyone holding a session attach their own chat. So
      # replacement is explicit and costs a code from the chat being replaced.
      #
      # A user who has lost the old chat entirely cannot do this, and belongs
      # in unlink_after_external_proof instead.
      #
      # Returns a LinkRequest, or the VerificationResult that stopped it.
      def start_chat_replacement(user_id, code)
        identity = @identities.find_by_user_id(user_id)

        return VerificationResult.failed(ErrorCode::NOT_LINKED) unless TelegramTwoFactor.verified?(identity)

        # Captured *before* verifying, because this is the enrollment the user
        # is about to prove possession of. It is what the token must record.
        proven = identity.generation

        proof = verify(user_id, code, PURPOSE_REPLACE)

        return proof unless proof.ok?

        if proven.nil? || proven.empty?
          # A row enrolled before the generation existed. Assign one,
          # conditional on it still being absent - which doubles as the check
          # below: if anything changed the enrollment while the code was being
          # verified, the generation is no longer absent and this declines.
          assigned = @identities.transition(user_id, identity.chat_id, nil,
                                            @codes.enrollment_generation)

          return VerificationResult.failed(ErrorCode::EXPIRED) unless TelegramTwoFactor.verified?(assigned)

          return mint_replacement_token(user_id, assigned.generation)
        end

        # Confirm the enrollment did not move while the code was being
        # verified, and reject if it did. What must never happen is adopting
        # the generation read *after* verification: a recovery landing in that
        # window would have its own new generation, and recording that would
        # hand this token authority over an enrollment the user never proved.
        after = @identities.find_by_user_id(user_id)

        unless TelegramTwoFactor.verified?(after) &&
               after.generation.is_a?(String) &&
               OpenSSL.secure_compare(after.generation, proven)
          @logger.warn("telegram-2fa: enrollment changed during replacement authorisation",
                       { user_id: user_id })

          return VerificationResult.failed(ErrorCode::EXPIRED)
        end

        mint_replacement_token(user_id, proven)
      end

      # ----------------------------------------------------------- challenge

      # Issue a code and send it to the linked chat.
      #
      # The code is not in the return value. It is generated, hashed into the
      # store, handed to Telegram, and dropped.
      def push(user_id, purpose = PURPOSE_LOGIN)
        identity = @identities.find_by_user_id(user_id)

        return ChallengeResult.failed(ErrorCode::NOT_LINKED) unless TelegramTwoFactor.verified?(identity)

        blocked = reserve_send(user_id)

        return ChallengeResult.failed(ErrorCode::COOLDOWN, blocked) unless blocked.nil?

        code, challenge_id = issue(user_id, purpose, identity.generation)

        unless @telegram.send_message(identity.chat_id, @messages.code(code, @config.code_ttl))
          # Drop the code rather than leaving one live that the user never
          # received. Conditionally, so a slow failure cannot delete a code
          # issued after it.
          discard_challenge(user_id, challenge_id)
          @logger.error("telegram-2fa: delivery failed", { user_id: user_id })

          return ChallengeResult.failed(ErrorCode::SEND_FAILED)
        end

        @logger.info("telegram-2fa: code sent", { user_id: user_id, purpose: purpose })

        ChallengeResult.sent(@clock.now + @config.code_ttl, @clock.now + @config.cooldown)
      end

      # The user asked the bot for a code.
      #
      # Writes the same store key as push, so one verification call accepts a
      # code from either direction - see the single-key rule in SPEC.md 4.
      def pull(chat_id, purpose = PURPOSE_ON_DEMAND)
        identity = @identities.find_by_chat_id(chat_id)

        return ChallengeResult.failed(ErrorCode::NOT_LINKED) unless TelegramTwoFactor.verified?(identity)

        blocked = reserve_send(identity.user_id)

        return ChallengeResult.failed(ErrorCode::COOLDOWN, blocked) unless blocked.nil?

        code, challenge_id = issue(identity.user_id, purpose, identity.generation)

        unless @telegram.send_message(chat_id, @messages.code(code, @config.code_ttl))
          discard_challenge(identity.user_id, challenge_id)

          return ChallengeResult.failed(ErrorCode::SEND_FAILED)
        end

        @logger.info("telegram-2fa: code issued on demand", { user_id: identity.user_id })

        ChallengeResult.sent(@clock.now + @config.code_ttl, @clock.now + @config.cooldown)
      end

      # -------------------------------------------------------- verification

      # Check a submitted code.
      #
      # Single use on success, attempt-budgeted on failure, constant-time
      # throughout. +purpose+ must match what the code was issued for and
      # defaults to login exactly as push does; there is deliberately no way to
      # skip the check, because a default of "compare against nothing" means
      # the binding does nothing unless every call site opts in, and the call
      # site that forgets is the one that matters.
      def verify(user_id, code, purpose = PURPOSE_LOGIN)
        key = @config.key("code", user_id)

        # Take the record, rather than read it and delete it later. Those are
        # two operations with a gap between them, and two verifications
        # arriving together both read the live record, both match, and both
        # succeed - a single-use code used twice, with the attempt counter
        # losing increments to the same race.
        record = @store.take(key)

        return VerificationResult.failed(ErrorCode::EXPIRED) unless record.is_a?(Hash) &&
                                                                    record["hash"].is_a?(String)

        attempts = record["attempts"].to_i

        # The record is already gone in each of these branches, which is what
        # we want: a spent or expired code should not come back.
        return VerificationResult.failed(ErrorCode::TOO_MANY_ATTEMPTS, 0) if attempts >= @config.max_attempts
        return VerificationResult.failed(ErrorCode::EXPIRED) if record["expires_at"].to_i < @clock.now

        # The enrollment this challenge belongs to must still be current.
        # Anything that changed it revoked this challenge, and the record is
        # already gone because we took it. This check, not the cleanup in bind,
        # is what makes revocation sound: cleanup races a concurrent
        # verification, while this cannot.
        unless generation_matches?(user_id, record["generation"])
          @logger.warn("telegram-2fa: challenge from a superseded enrollment", { user_id: user_id })

          return VerificationResult.failed(ErrorCode::EXPIRED)
        end

        # A code minted to confirm a login should not also confirm a
        # withdrawal. Count it as an attempt rather than a free retry, and
        # report invalid: telling the caller a live code exists for some other
        # purpose is information it has not proved it should have.
        unless purpose_satisfied?(record["purpose"].to_s, purpose)
          return record_failed_attempt(key, record, attempts, user_id)
        end

        unless @hasher.matches?(record["hash"], code.to_s.strip, user_id)
          return record_failed_attempt(key, record, attempts, user_id)
        end

        @logger.info("telegram-2fa: verified", { user_id: user_id, purpose: record["purpose"] })

        VerificationResult.passed
      end

      # ----------------------------------------------------------- unlinking

      # Remove the factor, proving possession of it first.
      #
      # Unlinking is the step an attacker with a stolen session but no phone
      # needs, so it demands the same proof as any other protected action.
      def unlink(user_id, code)
        identity = @identities.find_by_user_id(user_id)

        return VerificationResult.failed(ErrorCode::NOT_LINKED) unless TelegramTwoFactor.verified?(identity)

        # Under PURPOSE_UNLINK, so a code pushed for a login cannot remove the
        # factor. A code the user fetched with /code still works, because
        # on-demand codes are general-purpose.
        result = verify(user_id, code, PURPOSE_UNLINK)

        return result unless result.ok?

        # The enrollment moved while we were verifying, so the code we just
        # accepted no longer refers to what is stored.
        return VerificationResult.failed(ErrorCode::EXPIRED) unless detach(identity, identity.generation)

        VerificationResult.passed
      end

      # Remove the factor when another factor has already proved the request.
      #
      # For recovery paths: the user still has their authenticator, or passed
      # an out-of-band check, but has lost the Telegram account. The caller
      # takes responsibility for that proof - this method performs none.
      def unlink_after_external_proof(user_id, reason)
        identity = @identities.find_by_user_id(user_id)

        return false if identity.nil?

        # Unconditional: the caller has proved identity by other means, and a
        # recovery must not be blocked by whatever the account's state is.
        detach(identity, ANY_GENERATION)

        @logger.warn("telegram-2fa: unlinked via external proof",
                     { user_id: user_id, reason: reason })

        true
      end

      private

      # Store a replacement token against exactly one enrollment generation.
      #
      # Separate so there is a single place the generation is written, and so
      # no caller can pass one it read later than the proof.
      def mint_replacement_token(user_id, proven_generation)
        token = @codes.deep_link_token
        expires_at = @clock.now + @config.link_ttl

        # The replace mark lives on the stored token, not on the call that
        # resolves it. Taking it from the resolution side would make the proof
        # skippable by presenting an ordinary token.
        @store.put(
          @config.key("link", @hasher.hash(token)),
          {
            "user_id" => user_id,
            "expires_at" => expires_at,
            "replace" => true,
            "generation" => proven_generation
          },
          @config.link_ttl
        )

        @logger.info("telegram-2fa: chat replacement authorised", { user_id: user_id })

        LinkRequest.new(token: token, expires_at: expires_at,
                        url: @config.deep_link_url(token))
      end

      # Record the enrollment, as one conditional transition.
      #
      # Everything here hangs on handing the store an expectation rather than
      # reading state and then writing it. The validation above happens a
      # moment earlier, and a recovery or a competing link can land in between;
      # passing the generation we believed was current means such a write fails
      # instead of overwriting whatever replaced it.
      def bind(user_id, chat_id, replace: false, proven_generation: nil)
        existing = @identities.find_by_user_id(user_id)
        replacing = nil

        if TelegramTwoFactor.verified?(existing)
          # Re-presenting the same chat is a double submit, not a conflict.
          return LinkResult.linked(existing) if existing.chat_id == chat_id
          return LinkResult.failed(ErrorCode::ALREADY_LINKED) unless replace

          replacing = existing
        end

        expected = replace ? proven_generation : existing&.generation
        holder = @identities.find_by_chat_id(chat_id)

        if !holder.nil? && holder.user_id != user_id
          @logger.warn("telegram-2fa: chat already linked to another account",
                       { user_id: user_id })

          return LinkResult.failed(ErrorCode::ALREADY_LINKED)
        end

        begin
          # One write. It either moves the enrollment or changes nothing, so a
          # replacement onto an unavailable chat - or one overtaken by a
          # recovery - leaves the existing enrollment exactly as it was, rather
          # than stripping the account of its second factor as a side effect of
          # a request that failed.
          identity = @identities.transition(user_id, chat_id, expected,
                                            @codes.enrollment_generation)
        rescue ChatAlreadyLinked
          # The store's uniqueness constraint caught what the check above raced
          # past. The loser's existing enrollment is untouched.
          return LinkResult.failed(ErrorCode::ALREADY_LINKED)
        end

        if identity.nil?
          @logger.warn("telegram-2fa: enrollment changed during link",
                       { user_id: user_id, replace: replace })

          return LinkResult.failed(replace ? ErrorCode::INVALID_TOKEN : ErrorCode::ALREADY_LINKED)
        end

        unless replacing.nil?
          # Any code in flight was delivered to the chat that is no longer the
          # factor. The generation has already changed, so such a code is
          # unusable even if this cleanup loses a race; this stops it
          # lingering.
          clear_pending(user_id)

          # Afterwards, so a failed replacement never announces one.
          unless replacing.chat_id.nil?
            @telegram.send_message(replacing.chat_id, @messages.unlinked(@config.app_name))
          end

          @logger.info("telegram-2fa: factor replaced", { user_id: user_id })

          return LinkResult.linked(identity)
        end

        @logger.info("telegram-2fa: linked", { user_id: user_id })

        LinkResult.linked(identity)
      end

      def issue(user_id, purpose, generation)
        code = @codes.two_factor_code(@config.code_length)
        challenge_id = @codes.challenge_id

        @store.put(
          @config.key("code", user_id),
          {
            # Bound to the account, so a digest lifted from the store cannot be
            # matched against another user's code.
            "hash" => @hasher.hash(code, user_id),
            "expires_at" => @clock.now + @config.code_ttl,
            "attempts" => 0,
            "purpose" => purpose,
            "generation" => generation,
            "challenge_id" => challenge_id
          },
          @config.code_ttl
        )

        [code, challenge_id]
      end

      # Drop a challenge only if it is still the one we issued.
      #
      # A delivery failure must not delete a newer challenge. That is
      # reachable: if sending blocks past the cooldown, the user can be issued a
      # fresh code before this handler runs, and an unconditional delete would
      # throw away a code the user is holding.
      def discard_challenge(user_id, challenge_id)
        key = @config.key("code", user_id)
        record = @store.take(key)

        return unless record.is_a?(Hash)

        if record["challenge_id"] != challenge_id
          # Someone else's challenge. Put it back as we found it.
          @store.put(key, record, [1, record["expires_at"].to_i - @clock.now].max)

          return
        end

        @store.forget(@config.key("cooldown", user_id))
      end

      # Reserve the right to send, atomically.
      #
      # Checking for a cooldown and then writing one is two operations, and two
      # challenges arriving together both see no cooldown and both send. add
      # makes the write itself the check.
      def reserve_send(user_id)
        key = @config.key("cooldown", user_id)
        next_send_at = @clock.now + @config.cooldown

        return nil if @store.add(key, next_send_at, @config.cooldown)

        held = @store.get(key)

        # Coerced, not compared: a store may hand back a numeric string.
        Integer(held, 10)
      rescue ArgumentError, TypeError
        next_send_at
      end

      def clear_pending(user_id)
        @store.forget(@config.key("code", user_id))
        @store.forget(@config.key("cooldown", user_id))
      end

      # Whether a stored code may be used for the purpose being requested.
      #
      # An on-demand code is general-purpose by default, because it cannot know
      # what it is for and the user asked for it deliberately. That is a policy
      # rather than a law, so on_demand_satisfies can narrow it.
      def purpose_satisfied?(stored, requested)
        return true if stored == requested
        return false unless stored == PURPOSE_ON_DEMAND

        @config.on_demand_satisfies.nil? ||
          @config.on_demand_satisfies.include?(requested)
      end

      # Whether a challenge belongs to the account's current enrollment.
      #
      # A challenge issued before the generation existed (a row migrated from
      # an older version) is accepted only while the account has no generation
      # at all, so upgrading does not invalidate codes in flight.
      def generation_matches?(user_id, generation)
        current = @identities.find_by_user_id(user_id)&.generation

        return generation.nil? if current.nil?

        generation.is_a?(String) && OpenSSL.secure_compare(current, generation)
      end

      def generation_current?(user_id, generation)
        return false unless generation.is_a?(String) && !generation.empty?

        identity = @identities.find_by_user_id(user_id)

        return false unless TelegramTwoFactor.verified?(identity) && identity.generation.is_a?(String)

        OpenSSL.secure_compare(identity.generation, generation)
      end

      def record_failed_attempt(key, record, attempts, user_id)
        spent = attempts + 1
        remaining = @config.max_attempts - spent

        return VerificationResult.failed(ErrorCode::TOO_MANY_ATTEMPTS, 0) if remaining <= 0

        # Re-store under the code's own remaining lifetime. A fresh full TTL
        # would let an attacker keep a code alive indefinitely by guessing
        # wrong, removing the time limit altogether.
        #
        # A revocation can land between the take above and this write, so this
        # re-check keeps a dead challenge from being written back. It is
        # best-effort by nature, and does not need to be airtight, because
        # verify re-checks the generation before accepting anything. A
        # resurrected record is inert.
        if generation_matches?(user_id, record["generation"])
          @store.put(key, record.merge("attempts" => spent),
                     [1, record["expires_at"].to_i - @clock.now].max)
        end

        VerificationResult.failed(ErrorCode::INVALID, remaining)
      end

      # Remove the enrollment and revoke everything that referred to it.
      #
      # The generation is advanced even though no chat remains, which is the
      # whole reason it is stored separately from the chat id: a replacement
      # token or a challenge minted before this point stays void afterwards,
      # and would otherwise come back to life the moment the user links again.
      def detach(identity, expected)
        moved = @identities.transition(identity.user_id, nil, expected,
                                       @codes.enrollment_generation)

        if moved.nil?
          @logger.warn("telegram-2fa: enrollment changed during unlink",
                       { user_id: identity.user_id })

          return false
        end

        clear_pending(identity.user_id)

        # Best effort: the user should hear that their factor was removed even
        # if, especially if, they did not do it themselves.
        unless identity.chat_id.nil?
          @telegram.send_message(identity.chat_id, @messages.unlinked(@config.app_name))
        end

        @logger.info("telegram-2fa: unlinked", { user_id: identity.user_id })

        true
      end
    end
  end
end
