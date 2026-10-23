using System.Globalization;
using System.Text.RegularExpressions;

namespace Kampe.TelegramTwoFactor;

/// <summary>
/// Validated configuration.
/// </summary>
/// <remarks>
/// The constructor rejects a configuration that cannot be secure, rather than
/// accepting it and logging a warning nobody reads. A missing webhook secret is
/// the clearest case: with one absent, the webhook is an open endpoint that will
/// mint a code for any chat id a stranger posts to it, and the application looks
/// like it works. Failing at startup is the only version of that outcome anyone
/// notices.
/// </remarks>
public sealed partial class Config
{
    /// <summary>Creates and validates a configuration.</summary>
    /// <exception cref="ConfigurationException">The configuration cannot be secure.</exception>
    public Config(
        string botToken,
        string webhookSecret,
        string hashPepper,
        string? botUsername = null,
        string appName = "Kampe",
        int codeLength = 6,
        int codeTtl = 300,
        int cooldown = 120,
        int maxAttempts = 5,
        int linkCodeLength = 8,
        int linkTtl = 600,
        string keyPrefix = "tg2fa",
        string hashAlgorithm = "sha256",
        bool dedupeUpdates = true,
        int updateDedupeTtl = 3600,
        bool restrictWebhookIps = false,
        IReadOnlyList<string>? onDemandSatisfies = null)
    {
        BotToken = botToken ?? string.Empty;
        WebhookSecret = webhookSecret ?? string.Empty;
        HashPepper = hashPepper ?? string.Empty;
        BotUsername = botUsername;
        AppName = appName;
        CodeLength = codeLength;
        CodeTtl = codeTtl;
        Cooldown = cooldown;
        MaxAttempts = maxAttempts;
        LinkCodeLength = linkCodeLength;
        LinkTtl = linkTtl;
        KeyPrefix = keyPrefix;
        HashAlgorithm = hashAlgorithm;
        DedupeUpdates = dedupeUpdates;
        UpdateDedupeTtl = updateDedupeTtl;
        RestrictWebhookIps = restrictWebhookIps;
        OnDemandSatisfies = onDemandSatisfies;

        Validate();
    }

    /// <summary>The bot token from @BotFather.</summary>
    public string BotToken { get; }

    /// <summary>The secret Telegram echoes on every webhook request.</summary>
    public string WebhookSecret { get; }

    /// <summary>The HMAC key for code hashes.</summary>
    public string HashPepper { get; }

    /// <summary>The bot's username, needed only for deeplink URLs.</summary>
    public string? BotUsername { get; }

    /// <summary>The application name shown in bot copy.</summary>
    public string AppName { get; }

    /// <summary>Digits in a verification code.</summary>
    public int CodeLength { get; }

    /// <summary>How long a code stays valid, in seconds.</summary>
    public int CodeTtl { get; }

    /// <summary>The minimum gap between sends, in seconds.</summary>
    public int Cooldown { get; }

    /// <summary>Guesses allowed against one code.</summary>
    public int MaxAttempts { get; }

    /// <summary>Characters in a paste-flow link code.</summary>
    public int LinkCodeLength { get; }

    /// <summary>How long a link token stays resolvable, in seconds.</summary>
    public int LinkTtl { get; }

    /// <summary>The store key namespace.</summary>
    public string KeyPrefix { get; }

    /// <summary>The HMAC hash algorithm.</summary>
    public string HashAlgorithm { get; }

    /// <summary>Whether repeated update ids are dropped.</summary>
    public bool DedupeUpdates { get; }

    /// <summary>How long a handled update id is remembered, in seconds.</summary>
    public int UpdateDedupeTtl { get; }

    /// <summary>Whether to require the peer address to be Telegram's.</summary>
    public bool RestrictWebhookIps { get; }

    /// <summary>
    /// Which purposes a code fetched with /code satisfies; null for any.
    /// </summary>
    public IReadOnlyList<string>? OnDemandSatisfies { get; }

    /// <summary>Builds from environment variables, for the common case.</summary>
    public static Config FromEnvironment(IReadOnlyDictionary<string, string?>? environment = null)
    {
        var env = environment ?? ReadProcessEnvironment();

        return new Config(
            botToken: Value(env, "TELEGRAM_BOT_TOKEN") ?? string.Empty,
            webhookSecret: Value(env, "TELEGRAM_WEBHOOK_SECRET") ?? string.Empty,
            hashPepper: Value(env, "TELEGRAM_2FA_HASH_PEPPER") ?? string.Empty,
            botUsername: Value(env, "TELEGRAM_BOT_USERNAME"),
            appName: Value(env, "TELEGRAM_2FA_APP_NAME") ?? "Kampe",
            codeTtl: Integer(env, "TELEGRAM_2FA_CODE_TTL", 300),
            cooldown: Integer(env, "TELEGRAM_2FA_COOLDOWN", 120),
            maxAttempts: Integer(env, "TELEGRAM_2FA_MAX_ATTEMPTS", 5));
    }

    /// <summary>A store key, in the layout of SPEC.md section 9.</summary>
    public string Key(string kind, string identifier) => $"{KeyPrefix}:{kind}:{identifier}";

    /// <summary>The t.me link for a deeplink token, or null without a bot username.</summary>
    public string? DeepLinkUrl(string token) =>
        BotUsername is null ? null : $"https://t.me/{BotUsername}?start={token}";

    /// <summary>A value suitable for the webhook secret or the hash pepper.</summary>
    public static string GenerateSecret() => new CodeGenerator().WebhookSecret();

    private static Dictionary<string, string?> ReadProcessEnvironment()
    {
        var result = new Dictionary<string, string?>(StringComparer.Ordinal);

        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            result[(string)entry.Key] = entry.Value as string;
        }

        return result;
    }

    private static string? Value(IReadOnlyDictionary<string, string?> env, string key) =>
        env.TryGetValue(key, out var raw) && !string.IsNullOrEmpty(raw) ? raw : null;

    // Parsed strictly. int.TryParse on "5 attempts" fails, but a lenient parse -
    // or the Ruby equivalent of to_i - would read it as 5, and "nonsense" as 0,
    // turning a typo in the environment into a silently wrong security parameter.
    private static int Integer(IReadOnlyDictionary<string, string?> env, string key, int fallback)
    {
        var raw = Value(env, key);

        if (raw is null)
        {
            return fallback;
        }

        if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
        {
            throw new ConfigurationException($"{key} must be a whole number; received \"{raw}\".");
        }

        return parsed;
    }

    private void Validate()
    {
        if (string.IsNullOrWhiteSpace(BotToken))
        {
            throw new ConfigurationException(
                "A bot token is required. Create a bot with @BotFather and set TELEGRAM_BOT_TOKEN.");
        }

        if (!BotTokenPattern().IsMatch(BotToken))
        {
            throw new ConfigurationException(
                "The bot token is not in the format @BotFather issues (123456789:AA...). " +
                "Check that the value was not truncated or quoted.");
        }

        // Telegram accepts 1 to 256 characters here. One character would satisfy
        // Telegram and defeat the purpose, so the floor is ours.
        if (!WebhookSecretPattern().IsMatch(WebhookSecret))
        {
            throw new ConfigurationException(
                "The webhook secret must be 32 to 256 characters of A-Z, a-z, 0-9, underscore or " +
                "hyphen. Generate one with Config.GenerateSecret() and set TELEGRAM_WEBHOOK_SECRET. " +
                "This is what stops a stranger forging updates against your webhook; it is not optional.");
        }

        // Required, not recommended. A six-digit code has a million possible
        // values, so an unkeyed digest of one is reversed by a table anyone can
        // build in seconds: without a key, hashing the codes protects nothing
        // against someone who reads the store.
        if (HashPepper.Length < 32)
        {
            throw new ConfigurationException(
                "hashPepper must be at least 32 characters. It is the HMAC key for code hashes, and " +
                "without it a dumped cache of six-digit code hashes is reversed by a lookup table of " +
                "a million entries. Keep it outside the store it protects.");
        }

        if (BotUsername is not null && !BotUsernamePattern().IsMatch(BotUsername))
        {
            throw new ConfigurationException(
                "The bot username must be 5 to 32 characters of A-Z, a-z, 0-9 or underscore, " +
                "with no leading @.");
        }

        if (CodeLength is < 6 or > 8)
        {
            throw new ConfigurationException("codeLength must be between 6 and 8.");
        }

        if (CodeTtl is < 30 or > 600)
        {
            throw new ConfigurationException(
                "codeTtl must be between 30 and 600 seconds. A code that outlives the step it " +
                "authorises is a code sitting in a chat history waiting to be reused.");
        }

        if (Cooldown < 30)
        {
            throw new ConfigurationException(
                "cooldown must be at least 30 seconds, or the bot becomes a way to spam someone " +
                "via your bot token.");
        }

        if (MaxAttempts is < 1 or > 10)
        {
            throw new ConfigurationException(
                "maxAttempts must be between 1 and 10. Unlimited attempts against a six-digit code " +
                "is not two-factor authentication.");
        }

        if (LinkCodeLength < 8)
        {
            throw new ConfigurationException(
                "linkCodeLength must be at least 8. Paste-flow codes are stored under a key derived " +
                "from the code, so they share one namespace across every user and a short code is " +
                "enumerable.");
        }

        if (LinkTtl is < 60 or > 900)
        {
            throw new ConfigurationException("linkTtl must be between 60 and 900 seconds.");
        }

        if (UpdateDedupeTtl < 1)
        {
            throw new ConfigurationException("updateDedupeTtl must be a positive number of seconds.");
        }

        if (string.IsNullOrEmpty(KeyPrefix) || KeyPrefix.Contains(':', StringComparison.Ordinal))
        {
            throw new ConfigurationException(
                "keyPrefix must be non-empty and must not contain a colon.");
        }

        if (!CodeHasher.Supports(HashAlgorithm))
        {
            throw new ConfigurationException($"Unknown hash algorithm \"{HashAlgorithm}\".");
        }

        ValidateOnDemand();
    }

    private void ValidateOnDemand()
    {
        if (OnDemandSatisfies is null)
        {
            return;
        }

        if (OnDemandSatisfies.Count == 0)
        {
            throw new ConfigurationException(
                "onDemandSatisfies must list at least one purpose, or be null for any. An empty list " +
                "makes every code fetched with /code useless.");
        }

        if (OnDemandSatisfies.Any(string.IsNullOrEmpty))
        {
            throw new ConfigurationException("onDemandSatisfies must contain non-empty strings.");
        }
    }

    [GeneratedRegex(@"^\d+:[A-Za-z0-9_-]{30,}$")]
    private static partial Regex BotTokenPattern();

    [GeneratedRegex("^[A-Za-z0-9_-]{32,256}$")]
    private static partial Regex WebhookSecretPattern();

    [GeneratedRegex("^[A-Za-z0-9_]{5,32}$")]
    private static partial Regex BotUsernamePattern();
}
