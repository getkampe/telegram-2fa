using System.Net;
using System.Net.Sockets;

namespace Kampe.TelegramTwoFactor.Webhook;

/// <summary>
/// Decides whether a request on the webhook endpoint came from Telegram.
/// </summary>
/// <remarks>
/// This is the most important check in the library. The webhook URL is public and
/// unauthenticated, and what it accepts is an assertion of the form "this chat id
/// is asking for a code". Without verification, anyone who learns the URL can post
/// an update carrying a chat id and have the bot mint a code for whichever account
/// that chat is linked to - and because the code then arrives in the real owner's
/// chat, nothing in the application looks wrong.
/// <para>
/// Telegram supports this directly: register the webhook with a secret_token and it
/// sends that token in a header on every request.
/// </para>
/// </remarks>
public sealed class WebhookVerifier
{
    /// <summary>The header Telegram sends the secret token in.</summary>
    public const string SecretHeader = "X-Telegram-Bot-Api-Secret-Token";

    /// <summary>Telegram's published webhook source ranges.</summary>
    public static readonly IReadOnlyList<string> TelegramRanges =
        new[] { "149.154.160.0/20", "91.108.4.0/22" };

    private static readonly (IPAddress Network, int Prefix)[] Networks = TelegramRanges
        .Select(ParseCidr)
        .ToArray();

    private readonly Config _config;

    /// <summary>Creates the verifier.</summary>
    public WebhookVerifier(Config config) =>
        _config = config ?? throw new ArgumentNullException(nameof(config));

    /// <summary>
    /// Whether this request is Telegram's.
    /// </summary>
    /// <param name="headerValue">The value of <see cref="SecretHeader"/>.</param>
    /// <param name="remoteIp">The peer address, when IP restriction is enabled.</param>
    public bool Accepts(string? headerValue, string? remoteIp = null)
    {
        if (string.IsNullOrEmpty(headerValue))
        {
            return false;
        }

        // Fixed-time, so the time taken to reject does not reveal how much of the
        // secret was right. The length check is inside ConstantTime.Equals, and comes
        // first there because a fixed-time comparison is only fixed-time for equal
        // lengths - and a secret's length is not itself a secret.
        if (!ConstantTime.Equals(_config.WebhookSecret, headerValue))
        {
            return false;
        }

        return !_config.RestrictWebhookIps || IsFromTelegram(remoteIp);
    }

    /// <summary>
    /// Whether an address falls inside Telegram's published ranges.
    /// </summary>
    /// <remarks>
    /// Only meaningful if <paramref name="remoteIp"/> is the real peer. Behind a load
    /// balancer the peer is the proxy and the client address comes from a header the
    /// caller can set at will, which is why this is off by default and the secret
    /// token is not.
    /// </remarks>
    public static bool IsFromTelegram(string? remoteIp)
    {
        if (string.IsNullOrEmpty(remoteIp))
        {
            return false;
        }

        if (!TryParseAddress(remoteIp, out var address))
        {
            return false;
        }

        // An IPv4 address arriving as ::ffff:149.154.160.1, which is how Kestrel
        // reports one on a dual-stack socket. Without this the check would silently
        // never match.
        if (address!.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var candidate = address.GetAddressBytes();

        foreach (var (network, prefix) in Networks)
        {
            if (Contains(network.GetAddressBytes(), prefix, candidate))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryParseAddress(string value, out IPAddress? address)
    {
        var trimmed = value.Trim();

        // RemoteAddr-style "host:port", which is the obvious thing to pass in and
        // would otherwise never match.
        if (IPEndPoint.TryParse(trimmed, out var endpoint) && trimmed.Contains(':', StringComparison.Ordinal)
            && endpoint.Port != 0)
        {
            address = endpoint.Address;

            return true;
        }

        return IPAddress.TryParse(trimmed, out address);
    }

    private static bool Contains(byte[] network, int prefix, byte[] candidate)
    {
        if (network.Length != candidate.Length)
        {
            return false;
        }

        var wholeBytes = prefix / 8;
        var remainingBits = prefix % 8;

        for (var i = 0; i < wholeBytes; i++)
        {
            if (network[i] != candidate[i])
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));

        return (network[wholeBytes] & mask) == (candidate[wholeBytes] & mask);
    }

    private static (IPAddress Network, int Prefix) ParseCidr(string cidr)
    {
        var parts = cidr.Split('/');

        return (IPAddress.Parse(parts[0]), int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture));
    }
}
