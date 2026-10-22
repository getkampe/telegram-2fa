# frozen_string_literal: true

require "ipaddr"
require "openssl"

module Kampe
  module TelegramTwoFactor
    module Webhook
      # The header Telegram sends the secret token in.
      SECRET_HEADER = "X-Telegram-Bot-Api-Secret-Token"

      # Telegram's published webhook source ranges.
      TELEGRAM_RANGES = ["149.154.160.0/20", "91.108.4.0/22"].freeze

      # Decides whether a request on the webhook endpoint came from Telegram.
      #
      # This is the most important check in the library. The webhook URL is
      # public and unauthenticated, and what it accepts is an assertion of the
      # form "this chat id is asking for a code". Without verification, anyone
      # who learns the URL can post an update carrying a chat id and have the
      # bot mint a code for whichever account that chat is linked to - and
      # because the code then arrives in the real owner's chat, nothing in the
      # application looks wrong.
      #
      # Telegram supports this directly: register the webhook with a
      # secret_token and it sends that token in a header on every request.
      class Verifier
        def initialize(config)
          @config = config
          @ranges = TELEGRAM_RANGES.map { |cidr| IPAddr.new(cidr) }
        end

        def accepts?(header_value, remote_ip = nil)
          return false if header_value.nil? || header_value.to_s.empty?

          expected = @config.webhook_secret
          actual = header_value.to_s

          # secure_compare, so the time taken to reject does not reveal how
          # much of the secret was right. The length check comes first because
          # secure_compare raises on a mismatch, and a secret's length is not
          # itself a secret.
          return false unless expected.bytesize == actual.bytesize
          return false unless OpenSSL.secure_compare(expected, actual)
          return false if @config.restrict_webhook_ips && !from_telegram?(remote_ip)

          true
        end

        # Whether an address falls inside Telegram's published ranges.
        #
        # Only meaningful if remote_ip is the real peer. Behind a load balancer
        # the peer is the proxy and the client address comes from a header the
        # caller can set at will, which is why this is off by default and the
        # secret token is not.
        def from_telegram?(remote_ip)
          return false if remote_ip.nil? || remote_ip.to_s.empty?

          address = IPAddr.new(remote_ip.to_s)

          @ranges.any? { |range| range.include?(address) }
        rescue IPAddr::Error
          false
        end
      end

      # Turns a verified update into protocol actions.
      #
      # Framework-free: hand it a parsed update and it does the work. Routing,
      # body parsing and the secret-token check belong to the caller.
      #
      # Commands: /start (with or without a deeplink payload), /code, /status,
      # /link, /unlink, /help. Anything else gets a short reply rather than
      # silence, because silence from a security bot reads as a broken security
      # bot.
      class Handler
        def initialize(service:, config:, store:, telegram:, messages:,
                       logger: nil, clock: nil, account_label: nil)
          @service = service
          @config = config
          @store = store
          @telegram = telegram
          @messages = messages
          @logger = logger || NullLogger.new
          @clock = clock || SystemClock.new
          @account_label = account_label
          @extra = {}
        end

        # Register an application command, for example /balance.
        #
        # The block runs only after the update has been verified as coming from
        # Telegram, but the argument is still user input: treat it as such.
        def on(command, &block)
          @extra[command.to_s.sub(%r{\A/}, "").downcase] = block
          self
        end

        # Handle one update.
        #
        # Returns whether the update was acted on. Either way the caller should
        # answer 200: a non-2xx makes Telegram retry and queue every later
        # update behind this one.
        def handle(update)
          claim = claim_update(update)

          return false if claim == false

          begin
            handled = dispatch(update)
          rescue StandardError
            # Release the claim so Telegram's retry is processed rather than
            # discarded as a duplicate. Marking an update done before its work
            # succeeds turns one transient failure into a permanently lost
            # operation.
            @store.forget(claim) unless claim.nil?

            raise
          end

          # Only now is it really handled, so hold the claim for the full
          # window.
          @store.put(claim, "done", @config.update_dedupe_ttl) unless claim.nil?

          handled
        end

        private

        def dispatch(update)
          return handle_callback(update["callback_query"]) if update["callback_query"]

          message = update["message"]

          return false unless message.is_a?(Hash)

          chat = message["chat"] || {}
          chat_id = chat["id"]
          text = message["text"]

          return false if chat_id.nil? || !text.is_a?(String)

          chat_id = chat_id.to_s
          text = text.strip

          return false if text.empty?

          # Private chats only. A bot added to a group would otherwise hand out
          # verification codes in front of every member of it.
          return false unless (chat["type"] || "private") == "private"

          unless text.start_with?("/")
            # Codes travel application-to-user, never user-to-bot, so free text
            # is not a code to check. Nudging rather than parsing also means a
            # user who pastes a code into the wrong window has not handed it to
            # the bot.
            @telegram.send_message(chat_id, @messages.unknown_command)

            return false
          end

          command, argument = parse_command(text)

          @logger.info("telegram-2fa: command",
                       { command: command, update_id: update["update_id"] })

          case command
          when "start" then start(chat_id, argument)
          when "code", "otp", "2fa" then send_code(chat_id)
          when "status" then status(chat_id)
          when "link" then link(chat_id)
          when "unlink" then unlink_hint(chat_id)
          when "help" then help(chat_id)
          else dispatch_extra(command, chat_id, argument)
          end
        end

        def start(chat_id, payload)
          return help(chat_id) if payload.empty?

          result = @service.complete_deep_link(payload, chat_id)

          if result.ok? && !result.identity.nil?
            label = @account_label ? @account_label.call(result.identity.user_id) : "your account"
            @telegram.send_message(chat_id, @messages.link_succeeded(label, @config.app_name))

            return true
          end

          @telegram.send_message(
            chat_id,
            result.error == ErrorCode::ALREADY_LINKED ? @messages.already_linked : @messages.link_token_invalid
          )

          false
        end

        def link(chat_id)
          if TelegramTwoFactor.verified?(@service.identity_for_chat(chat_id))
            @telegram.send_message(chat_id, @messages.already_linked)

            return false
          end

          request = @service.start_paste_link(chat_id)

          @telegram.send_message(
            chat_id,
            @messages.link_instructions(request.token, @config.link_ttl, @config.app_name)
          )

          true
        end

        def send_code(chat_id)
          # pull sends the code itself, so the plaintext never reaches here.
          result = @service.pull(chat_id)

          return true if result.ok?

          text =
            case result.error
            when ErrorCode::NOT_LINKED then @messages.not_linked(@config.app_name)
            when ErrorCode::COOLDOWN then @messages.cooldown(result.retry_after(@clock.now))
            else @messages.unknown_command
            end

          @telegram.send_message(chat_id, text)

          false
        end

        def status(chat_id)
          linked = TelegramTwoFactor.verified?(@service.identity_for_chat(chat_id))

          @telegram.send_message(
            chat_id,
            linked ? @messages.welcome(true, @config.app_name) : @messages.not_linked(@config.app_name)
          )

          true
        end

        # /unlink explains where to do it, and does not do it.
        #
        # Whoever holds the phone can already read the codes; letting them also
        # remove the factor with no session and no password turns a stolen
        # phone into a permanently single-factor account.
        def unlink_hint(chat_id)
          unless TelegramTwoFactor.verified?(@service.identity_for_chat(chat_id))
            @telegram.send_message(chat_id, @messages.not_linked(@config.app_name))

            return false
          end

          @telegram.send_message(chat_id, @messages.unlink_instructions(@config.app_name))

          true
        end

        def help(chat_id)
          linked = TelegramTwoFactor.verified?(@service.identity_for_chat(chat_id))
          @telegram.send_message(chat_id, @messages.welcome(linked, @config.app_name))

          true
        end

        def dispatch_extra(command, chat_id, argument)
          handler = @extra[command]

          if handler.nil?
            @telegram.send_message(chat_id, @messages.unknown_command)

            return false
          end

          handler.call(chat_id, argument)

          true
        end

        def handle_callback(query)
          id = query["id"].to_s
          data = query["data"].to_s
          chat = (query["message"] || {})["chat"] || {}
          chat_id = chat["id"]

          # Acknowledge first, or the user's client spins for ten seconds.
          @telegram.answer_callback_query(id) unless id.empty?

          return false if chat_id.nil?

          chat_id = chat_id.to_s

          case data
          when "code" then send_code(chat_id)
          when "status" then status(chat_id)
          when "link" then link(chat_id)
          when "help" then help(chat_id)
          else false
          end
        end

        def parse_command(text)
          head, _, tail = text.partition(/\s+/)
          command = head.sub(%r{\A/}, "").downcase

          # In groups Telegram appends the bot name: /code@kampe_bot.
          command = command.split("@").first.to_s if command.include?("@")

          [command, tail.to_s.strip]
        end

        # Claim an update, so exactly one attempt processes it.
        #
        # Telegram retries an update it believes was not delivered, and
        # delivers concurrently, so the same update_id can arrive more than
        # once and at the same time. add is the whole mechanism: checking for a
        # marker and then writing one is two operations, and two simultaneous
        # deliveries both find nothing and both proceed.
        #
        # Returns the claim key, false when already claimed, or nil when
        # deduplication is off.
        def claim_update(update)
          return nil unless @config.dedupe_updates

          update_id = update["update_id"]

          return nil if update_id.nil?

          key = @config.key("update", update_id.to_s)

          # A short claim, not the full window: if this process dies
          # mid-handling the claim lapses on its own and a later retry can pick
          # the update up.
          ttl = [[@config.update_dedupe_ttl, 120].min, 30].max

          unless @store.add(key, "claimed", ttl)
            @logger.info("telegram-2fa: duplicate update dropped", { update_id: update_id })

            return false
          end

          key
        end
      end
    end
  end
end
