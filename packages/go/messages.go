package telegram2fa

import (
	"fmt"
	"strings"
	"time"
)

// EscapeHTML escapes text for parse_mode HTML.
//
// Telegram's HTML mode needs only these three characters escaped. Any message
// that interpolates a display name, an email or anything else a user controls
// must run it through here: unescaped, a name containing an angle bracket makes
// Telegram reject the message outright, which is the benign case.
func EscapeHTML(text string) string {
	text = strings.ReplaceAll(text, "&", "&amp;")
	text = strings.ReplaceAll(text, "<", "&lt;")

	return strings.ReplaceAll(text, ">", "&gt;")
}

func humanise(d time.Duration) string {
	seconds := int(d.Seconds())

	if seconds < 60 {
		if seconds == 1 {
			return "1 second"
		}

		return fmt.Sprintf("%d seconds", seconds)
	}

	minutes := (seconds + 30) / 60

	if minutes == 1 {
		return "1 minute"
	}

	return fmt.Sprintf("%d minutes", minutes)
}

// DefaultMessages is the bot's default English copy. Implement Messages to
// translate or restyle any of it.
type DefaultMessages struct{}

func (DefaultMessages) Code(code string, ttl time.Duration) string {
	return "🔐 <b>Verification code</b>\n\n" +
		"<code>" + code + "</code>\n\n" +
		"Valid for " + humanise(ttl) + ", once.\n" +
		"If you did not ask for this, someone has your password. " +
		"Do not enter the code, and change it now."
}

func (DefaultMessages) LinkInstructions(code string, ttl time.Duration, appName string) string {
	return "🔗 <b>Link this chat to " + EscapeHTML(appName) + "</b>\n\n" +
		"<code>" + code + "</code>\n\n" +
		"Enter this code on the Telegram setup page in your account settings.\n" +
		"It expires in " + humanise(ttl) + ". Tap it to copy."
}

func (DefaultMessages) LinkSucceeded(accountLabel, appName string) string {
	return "✅ <b>This chat is now your second factor for " + EscapeHTML(appName) + "</b>\n\n" +
		"Account: " + EscapeHTML(accountLabel) + "\n\n" +
		"Send /code any time you need a verification code.\n" +
		"If you did not do this, send /unlink immediately and change your password."
}

func (DefaultMessages) LinkTokenInvalid() string {
	return "❌ <b>That code did not work</b>\n\n" +
		"It has expired, has already been used, or was mistyped.\n\n" +
		"Start again from your account settings to get a fresh one."
}

func (DefaultMessages) AlreadyLinked() string {
	return "ℹ️ <b>Already linked</b>\n\n" +
		"This chat is already set up as a second factor.\n\n" +
		"Send /code for a verification code, or /unlink to remove it."
}

func (DefaultMessages) NotLinked(appName string) string {
	return "🔌 <b>This chat is not linked</b>\n\n" +
		"Open your " + EscapeHTML(appName) + " account settings and start the Telegram " +
		"setup, then come back here."
}

func (DefaultMessages) Cooldown(secondsRemaining int) string {
	return "⏳ <b>A code was just sent</b>\n\n" +
		"Check the message above, or ask again in " +
		humanise(time.Duration(secondsRemaining)*time.Second) + "."
}

func (DefaultMessages) UnlinkInstructions(appName string) string {
	return "🔓 <b>Removing Telegram as your second factor</b>\n\n" +
		"For your security this cannot be done from the chat — anyone holding your " +
		"phone could do it.\n\n" +
		"1. Sign in to " + EscapeHTML(appName) + " and open your security settings\n" +
		"2. Choose to remove Telegram\n" +
		"3. Send /code here and enter that code to confirm\n\n" +
		"Lost access to this account instead? Contact support — they can verify you " +
		"another way."
}

func (DefaultMessages) Unlinked(appName string) string {
	return "🔓 <b>No longer your second factor</b>\n\n" +
		"This chat has been unlinked from " + EscapeHTML(appName) + ".\n\n" +
		"If you did not do this, your account may be compromised: sign in, change " +
		"your password, and set up two-factor authentication again."
}

func (DefaultMessages) Welcome(isLinked bool, appName string) string {
	name := EscapeHTML(appName)

	if isLinked {
		return "👋 <b>" + name + " security bot</b>\n\n" +
			"This chat is linked and working.\n\n" +
			"/code — get a verification code\n" +
			"/status — show link details\n" +
			"/unlink — stop using this chat as a second factor\n" +
			"/help — this message"
	}

	return "👋 <b>" + name + " security bot</b>\n\n" +
		"I deliver verification codes for your " + name + " account.\n\n" +
		"To get started, open your account settings, begin the Telegram setup, and " +
		"follow the link or code it gives you.\n\n" +
		"/help — this message"
}

func (DefaultMessages) UnknownCommand() string {
	return "🤔 <b>I do not know that command</b>\n\n" +
		"Send /help to see what I can do."
}
