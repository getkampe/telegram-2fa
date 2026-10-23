# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module Kampe
  module TelegramTwoFactor
    # The default Telegram client: net/http, no gems.
    #
    # Duck-type this class to route through a queue, an existing bot library,
    # or an HTTP client you already use.
    class TelegramClient
      BASE = "https://api.telegram.org/bot"

      def initialize(bot_token, timeout: 10, logger: nil, parse_mode: "HTML")
        @bot_token = bot_token
        @timeout = timeout
        @logger = logger || NullLogger.new
        @parse_mode = parse_mode
      end

      def send_message(chat_id, text, inline_keyboard = nil)
        payload = {
          chat_id: chat_id,
          text: text,
          parse_mode: @parse_mode,
          disable_web_page_preview: true
        }

        payload[:reply_markup] = { inline_keyboard: inline_keyboard } unless inline_keyboard.nil?

        call("sendMessage", payload)

        true
      rescue RequestFailed => e
        # Delivery is fallible and the caller has a fallback path, so this is
        # reported rather than raised. The message body is never logged: for a
        # challenge, the body is the code.
        @logger.error("telegram-2fa: sendMessage failed", { reason: e.message })

        false
      end

      def answer_callback_query(callback_query_id, text = nil)
        payload = { callback_query_id: callback_query_id }
        payload[:text] = text unless text.nil?

        call("answerCallbackQuery", payload)

        true
      rescue RequestFailed
        false
      end

      def get_me
        result = call("getMe", {})

        result.is_a?(Hash) ? result : {}
      end

      def set_webhook(url, secret_token, allowed_updates = nil)
        unless url.start_with?("https://")
          raise RequestFailed,
                "Telegram will only deliver webhooks to an https URL with a valid certificate."
        end

        call("setWebhook", {
               url: url,
               secret_token: secret_token,
               allowed_updates: allowed_updates || %w[message callback_query],
               # Telegram queues updates while a webhook is unset or failing.
               # On a first deploy that queue can hold stale /code requests, so
               # it is dropped rather than replayed into a live 2FA flow.
               drop_pending_updates: true
             })

        true
      end

      def delete_webhook
        call("deleteWebhook", { drop_pending_updates: true })

        true
      end

      private

      def call(method, payload)
        uri = URI("#{BASE}#{@bot_token}/#{method}")

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        # Explicit, because a bot token travelling over an unverified
        # connection is a bot token handed to whoever is in the middle of it.
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.open_timeout = @timeout
        http.read_timeout = @timeout

        request = Net::HTTP::Post.new(uri.path, { "Content-Type" => "application/json" })
        request.body = JSON.generate(payload)

        response = http.request(request)
        body = JSON.parse(response.body)

        unless body["ok"] == true
          # Telegram's own description does not echo the message body back, so
          # it is safe to surface.
          raise RequestFailed,
                "Telegram rejected #{method} with status #{response.code}: " \
                "#{body['description'] || 'no description'}"
        end

        body.fetch("result", true)
      rescue JSON::ParserError
        raise RequestFailed, "Telegram returned a non-JSON response."
      rescue SystemCallError, Net::OpenTimeout, Net::ReadTimeout, OpenSSL::SSL::SSLError => e
        raise RequestFailed, "Telegram could not be reached: #{e.message}"
      end
    end
  end
end
