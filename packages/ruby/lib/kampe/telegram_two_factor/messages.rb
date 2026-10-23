# frozen_string_literal: true

module Kampe
  module TelegramTwoFactor
    # Escape text for parse_mode HTML.
    #
    # Telegram's HTML mode needs only these three characters escaped. Any
    # message that interpolates a display name, an email or anything else a
    # user controls must run it through here: unescaped, a name containing an
    # angle bracket makes Telegram reject the message outright, which is the
    # benign case.
    def self.escape_html(text)
      text.to_s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;")
    end

    # The bot's default English copy.
    #
    # Duck-type this class to translate or restyle any of it.
    class DefaultMessages
      def code(code, ttl_seconds)
        "🔐 <b>Verification code</b>\n\n" \
          "<code>#{code}</code>\n\n" \
          "Valid for #{humanise(ttl_seconds)}, once.\n" \
          "If you did not ask for this, someone has your password. " \
          "Do not enter the code, and change it now."
      end

      def link_instructions(code, ttl_seconds, app_name)
        "🔗 <b>Link this chat to #{TelegramTwoFactor.escape_html(app_name)}</b>\n\n" \
          "<code>#{code}</code>\n\n" \
          "Enter this code on the Telegram setup page in your account settings.\n" \
          "It expires in #{humanise(ttl_seconds)}. Tap it to copy."
      end

      def link_succeeded(account_label, app_name)
        "✅ <b>This chat is now your second factor for " \
          "#{TelegramTwoFactor.escape_html(app_name)}</b>\n\n" \
          "Account: #{TelegramTwoFactor.escape_html(account_label)}\n\n" \
          "Send /code any time you need a verification code.\n" \
          "If you did not do this, send /unlink immediately and change your password."
      end

      def link_token_invalid
        "❌ <b>That code did not work</b>\n\n" \
          "It has expired, has already been used, or was mistyped.\n\n" \
          "Start again from your account settings to get a fresh one."
      end

      def already_linked
        "ℹ️ <b>Already linked</b>\n\n" \
          "This chat is already set up as a second factor.\n\n" \
          "Send /code for a verification code, or /unlink to remove it."
      end

      def not_linked(app_name)
        "🔌 <b>This chat is not linked</b>\n\n" \
          "Open your #{TelegramTwoFactor.escape_html(app_name)} account settings and " \
          "start the Telegram setup, then come back here."
      end

      def cooldown(seconds_remaining)
        "⏳ <b>A code was just sent</b>\n\n" \
          "Check the message above, or ask again in #{humanise(seconds_remaining)}."
      end

      def unlink_instructions(app_name)
        "🔓 <b>Removing Telegram as your second factor</b>\n\n" \
          "For your security this cannot be done from the chat — anyone holding your " \
          "phone could do it.\n\n" \
          "1. Sign in to #{TelegramTwoFactor.escape_html(app_name)} and open your " \
          "security settings\n" \
          "2. Choose to remove Telegram\n" \
          "3. Send /code here and enter that code to confirm\n\n" \
          "Lost access to this account instead? Contact support — they can verify you " \
          "another way."
      end

      def unlinked(app_name)
        "🔓 <b>No longer your second factor</b>\n\n" \
          "This chat has been unlinked from #{TelegramTwoFactor.escape_html(app_name)}.\n\n" \
          "If you did not do this, your account may be compromised: sign in, change " \
          "your password, and set up two-factor authentication again."
      end

      def welcome(is_linked, app_name)
        name = TelegramTwoFactor.escape_html(app_name)

        if is_linked
          return "👋 <b>#{name} security bot</b>\n\n" \
                 "This chat is linked and working.\n\n" \
                 "/code — get a verification code\n" \
                 "/status — show link details\n" \
                 "/unlink — stop using this chat as a second factor\n" \
                 "/help — this message"
        end

        "👋 <b>#{name} security bot</b>\n\n" \
          "I deliver verification codes for your #{name} account.\n\n" \
          "To get started, open your account settings, begin the Telegram setup, and " \
          "follow the link or code it gives you.\n\n" \
          "/help — this message"
      end

      def unknown_command
        "🤔 <b>I do not know that command</b>\n\n" \
          "Send /help to see what I can do."
      end

      private

      def humanise(seconds)
        return "#{seconds} second#{seconds == 1 ? '' : 's'}" if seconds < 60

        minutes = (seconds / 60.0).round

        "#{minutes} minute#{minutes == 1 ? '' : 's'}"
      end
    end
  end
end
