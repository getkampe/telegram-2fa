"""The bot's default English copy."""

from __future__ import annotations


def escape_html(text: str) -> str:
    """Escape text for parse_mode HTML.

    Telegram's HTML mode needs only these three characters escaped. Any message
    that interpolates a display name, an email or anything else a user controls
    must run it through here: unescaped, a name containing an angle bracket
    makes Telegram reject the message outright, which is the benign case.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _humanise(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds} second" + ("" if seconds == 1 else "s")

    minutes = round(seconds / 60)

    return f"{minutes} minute" + ("" if minutes == 1 else "s")


class DefaultMessages:
    """Implement the Messages protocol to translate or restyle any of this."""

    def code(self, code: str, ttl_seconds: int) -> str:
        return (
            "🔐 <b>Verification code</b>\n\n"
            f"<code>{code}</code>\n\n"
            f"Valid for {_humanise(ttl_seconds)}, once.\n"
            "If you did not ask for this, someone has your password. "
            "Do not enter the code, and change it now."
        )

    def link_instructions(self, code: str, ttl_seconds: int, app_name: str) -> str:
        return (
            f"🔗 <b>Link this chat to {escape_html(app_name)}</b>\n\n"
            f"<code>{code}</code>\n\n"
            "Enter this code on the Telegram setup page in your account settings.\n"
            f"It expires in {_humanise(ttl_seconds)}. Tap it to copy."
        )

    def link_succeeded(self, account_label: str, app_name: str) -> str:
        return (
            "✅ <b>This chat is now your second factor for "
            f"{escape_html(app_name)}</b>\n\n"
            f"Account: {escape_html(account_label)}\n\n"
            "Send /code any time you need a verification code.\n"
            "If you did not do this, send /unlink immediately and change your password."
        )

    def link_token_invalid(self) -> str:
        return (
            "❌ <b>That code did not work</b>\n\n"
            "It has expired, has already been used, or was mistyped.\n\n"
            "Start again from your account settings to get a fresh one."
        )

    def already_linked(self) -> str:
        return (
            "ℹ️ <b>Already linked</b>\n\n"
            "This chat is already set up as a second factor.\n\n"
            "Send /code for a verification code, or /unlink to remove it."
        )

    def not_linked(self, app_name: str) -> str:
        return (
            "🔌 <b>This chat is not linked</b>\n\n"
            f"Open your {escape_html(app_name)} account settings and start the "
            "Telegram setup, then come back here."
        )

    def cooldown(self, seconds_remaining: int) -> str:
        return (
            "⏳ <b>A code was just sent</b>\n\n"
            f"Check the message above, or ask again in {_humanise(seconds_remaining)}."
        )

    def unlink_instructions(self, app_name: str) -> str:
        return (
            "🔓 <b>Removing Telegram as your second factor</b>\n\n"
            "For your security this cannot be done from the chat — anyone holding "
            "your phone could do it.\n\n"
            f"1. Sign in to {escape_html(app_name)} and open your security settings\n"
            "2. Choose to remove Telegram\n"
            "3. Send /code here and enter that code to confirm\n\n"
            "Lost access to this account instead? Contact support — they can verify "
            "you another way."
        )

    def unlinked(self, app_name: str) -> str:
        return (
            "🔓 <b>No longer your second factor</b>\n\n"
            f"This chat has been unlinked from {escape_html(app_name)}.\n\n"
            "If you did not do this, your account may be compromised: sign in, "
            "change your password, and set up two-factor authentication again."
        )

    def welcome(self, is_linked: bool, app_name: str) -> str:
        name = escape_html(app_name)

        if is_linked:
            return (
                f"👋 <b>{name} security bot</b>\n\n"
                "This chat is linked and working.\n\n"
                "/code — get a verification code\n"
                "/status — show link details\n"
                "/unlink — stop using this chat as a second factor\n"
                "/help — this message"
            )

        return (
            f"👋 <b>{name} security bot</b>\n\n"
            f"I deliver verification codes for your {name} account.\n\n"
            "To get started, open your account settings, begin the Telegram setup, "
            "and follow the link or code it gives you.\n\n"
            "/help — this message"
        )

    def unknown_command(self) -> str:
        return (
            "🤔 <b>I do not know that command</b>\n\n"
            "Send /help to see what I can do."
        )
