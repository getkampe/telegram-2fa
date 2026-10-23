using System.Globalization;

namespace Kampe.TelegramTwoFactor.Telegram;

/// <summary>Escaping for Telegram's HTML parse mode.</summary>
public static class Html
{
    /// <summary>
    /// Escapes text for parse_mode HTML.
    /// </summary>
    /// <remarks>
    /// Telegram's HTML mode needs only these three characters escaped. Any message
    /// that interpolates a display name, an email or anything else a user controls
    /// must run it through here: unescaped, a name containing an angle bracket makes
    /// Telegram reject the message outright, which is the benign case.
    /// </remarks>
    public static string Escape(string? text) =>
        (text ?? string.Empty)
            .Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);
}

/// <summary>
/// The bot's default English copy.
/// </summary>
/// <remarks>Implement <see cref="IMessages"/> to translate or restyle any of it.</remarks>
public class DefaultMessages : IMessages
{
    /// <inheritdoc />
    public virtual string Code(string code, int ttlSeconds) =>
        "🔐 <b>Verification code</b>\n\n" +
        $"<code>{code}</code>\n\n" +
        $"Valid for {Humanise(ttlSeconds)}, once.\n" +
        "If you did not ask for this, someone has your password. " +
        "Do not enter the code, and change it now.";

    /// <inheritdoc />
    public virtual string LinkInstructions(string code, int ttlSeconds, string appName) =>
        $"🔗 <b>Link this chat to {Html.Escape(appName)}</b>\n\n" +
        $"<code>{code}</code>\n\n" +
        "Enter this code on the Telegram setup page in your account settings.\n" +
        $"It expires in {Humanise(ttlSeconds)}. Tap it to copy.";

    /// <inheritdoc />
    public virtual string LinkSucceeded(string accountLabel, string appName) =>
        $"✅ <b>This chat is now your second factor for {Html.Escape(appName)}</b>\n\n" +
        $"Account: {Html.Escape(accountLabel)}\n\n" +
        "Send /code any time you need a verification code.\n" +
        "If you did not do this, send /unlink immediately and change your password.";

    /// <inheritdoc />
    public virtual string LinkTokenInvalid() =>
        "❌ <b>That code did not work</b>\n\n" +
        "It has expired, has already been used, or was mistyped.\n\n" +
        "Start again from your account settings to get a fresh one.";

    /// <inheritdoc />
    public virtual string AlreadyLinked() =>
        "ℹ️ <b>Already linked</b>\n\n" +
        "This chat is already set up as a second factor.\n\n" +
        "Send /code for a verification code, or /unlink to remove it.";

    /// <inheritdoc />
    public virtual string NotLinked(string appName) =>
        "🔌 <b>This chat is not linked</b>\n\n" +
        $"Open your {Html.Escape(appName)} account settings and start the Telegram setup, " +
        "then come back here.";

    /// <inheritdoc />
    public virtual string Cooldown(long secondsRemaining) =>
        "⏳ <b>A code was just sent</b>\n\n" +
        $"Check the message above, or ask again in {Humanise(secondsRemaining)}.";

    /// <inheritdoc />
    public virtual string UnlinkInstructions(string appName) =>
        "🔓 <b>Removing Telegram as your second factor</b>\n\n" +
        "For your security this cannot be done from the chat — anyone holding your phone " +
        "could do it.\n\n" +
        $"1. Sign in to {Html.Escape(appName)} and open your security settings\n" +
        "2. Choose to remove Telegram\n" +
        "3. Send /code here and enter that code to confirm\n\n" +
        "Lost access to this account instead? Contact support — they can verify you another way.";

    /// <inheritdoc />
    public virtual string Unlinked(string appName) =>
        "🔓 <b>No longer your second factor</b>\n\n" +
        $"This chat has been unlinked from {Html.Escape(appName)}.\n\n" +
        "If you did not do this, your account may be compromised: sign in, change your " +
        "password, and set up two-factor authentication again.";

    /// <inheritdoc />
    public virtual string Welcome(bool isLinked, string appName)
    {
        var name = Html.Escape(appName);

        if (isLinked)
        {
            return $"👋 <b>{name} security bot</b>\n\n" +
                   "This chat is linked and working.\n\n" +
                   "/code — get a verification code\n" +
                   "/status — show link details\n" +
                   "/unlink — stop using this chat as a second factor\n" +
                   "/help — this message";
        }

        return $"👋 <b>{name} security bot</b>\n\n" +
               $"I deliver verification codes for your {name} account.\n\n" +
               "To get started, open your account settings, begin the Telegram setup, and follow " +
               "the link or code it gives you.\n\n" +
               "/help — this message";
    }

    /// <inheritdoc />
    public virtual string UnknownCommand() =>
        "🤔 <b>I do not know that command</b>\n\n" +
        "Send /help to see what I can do.";

    private static string Humanise(long seconds)
    {
        if (seconds < 60)
        {
            return $"{seconds} second{(seconds == 1 ? string.Empty : "s")}";
        }

        var minutes = (long)Math.Round(seconds / 60.0, MidpointRounding.AwayFromZero);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{minutes} minute{(minutes == 1 ? string.Empty : "s")}");
    }
}
