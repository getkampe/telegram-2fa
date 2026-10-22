namespace Kampe.TelegramTwoFactor;

/// <summary>Base class for every error this library raises.</summary>
public class TelegramTwoFactorException : Exception
{
    /// <summary>Creates the exception.</summary>
    public TelegramTwoFactorException(string message) : base(message)
    {
    }

    /// <summary>Creates the exception, wrapping a cause.</summary>
    public TelegramTwoFactorException(string message, Exception inner) : base(message, inner)
    {
    }
}

/// <summary>
/// The configuration cannot produce a secure installation.
/// </summary>
/// <remarks>Thrown when the config is built, never mid-request.</remarks>
public sealed class ConfigurationException : TelegramTwoFactorException
{
    /// <summary>Creates the exception.</summary>
    public ConfigurationException(string message) : base(message)
    {
    }
}

/// <summary>Telegram refused a request, or could not be reached.</summary>
public sealed class TelegramRequestFailedException : TelegramTwoFactorException
{
    /// <summary>Creates the exception.</summary>
    public TelegramRequestFailedException(string message) : base(message)
    {
    }

    /// <summary>Creates the exception, wrapping a cause.</summary>
    public TelegramRequestFailedException(string message, Exception inner) : base(message, inner)
    {
    }
}

/// <summary>
/// A chat is already bound to a different account.
/// </summary>
/// <remarks>
/// Identity stores throw this rather than reassigning: one Telegram account
/// acting as the second factor for several accounts means one compromised
/// Telegram account compromises all of them.
/// </remarks>
public sealed class ChatAlreadyLinkedException : TelegramTwoFactorException
{
    /// <summary>Creates the exception.</summary>
    public ChatAlreadyLinkedException(string message) : base(message)
    {
    }
}
