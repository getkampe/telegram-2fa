using Kampe.TelegramTwoFactor.Webhook;
using Xunit;

namespace Kampe.TelegramTwoFactor.Tests;

/// <summary>
/// SPEC.md section 7. The check that matters most: without it the webhook accepts
/// a forged assertion that any chat id is asking for a code.
/// </summary>
public class VerifierTests
{
    [Fact]
    public void TheMatchingSecretIsAccepted() =>
        Assert.True(new WebhookVerifier(TestSupport.MakeConfig()).Accepts(TestSupport.Secret));

    [Fact]
    public void AWrongOrMissingSecretIsRejected()
    {
        var verifier = new WebhookVerifier(TestSupport.MakeConfig());

        foreach (var value in new[] { "", null, new string('x', 48) })
        {
            Assert.False(verifier.Accepts(value), $"{value ?? "null"} must be rejected");
        }
    }

    /// <summary>
    /// Truncating or length-insensitive comparisons are the classic way this gets
    /// written wrong.
    /// </summary>
    [Fact]
    public void APrefixOrExtensionOfTheSecretIsRejected()
    {
        var verifier = new WebhookVerifier(TestSupport.MakeConfig());

        Assert.False(verifier.Accepts(new string('s', 47)));
        Assert.False(verifier.Accepts(new string('s', 49)));
    }

    [Fact]
    public void IpRestrictionAcceptsTelegramRanges()
    {
        var verifier = new WebhookVerifier(TestSupport.MakeConfig(restrictWebhookIps: true));

        foreach (var address in new[] { "149.154.160.1", "149.154.175.254", "91.108.4.10" })
        {
            Assert.True(verifier.Accepts(TestSupport.Secret, address), address);
        }
    }

    [Fact]
    public void IpRestrictionRejectsEverythingElse()
    {
        var verifier = new WebhookVerifier(TestSupport.MakeConfig(restrictWebhookIps: true));

        foreach (var address in new[] { "8.8.8.8", "149.154.176.1", "127.0.0.1", null, "not-an-ip" })
        {
            Assert.False(verifier.Accepts(TestSupport.Secret, address), address ?? "null");
        }
    }

    /// <summary>
    /// Kestrel reports an IPv4 peer on a dual-stack socket as ::ffff:a.b.c.d, and
    /// a RemoteAddr-style value carries a port. Both are the obvious thing to pass
    /// in, and both would otherwise silently never match.
    /// </summary>
    [Fact]
    public void IpRestrictionUnderstandsMappedAddressesAndPorts()
    {
        var verifier = new WebhookVerifier(TestSupport.MakeConfig(restrictWebhookIps: true));

        Assert.True(verifier.Accepts(TestSupport.Secret, "::ffff:149.154.160.1"));
        Assert.True(verifier.Accepts(TestSupport.Secret, "149.154.160.1:443"));
        Assert.False(verifier.Accepts(TestSupport.Secret, "::ffff:8.8.8.8"));
    }

    /// <summary>
    /// Off by default because behind a proxy the peer address is the proxy, so the
    /// check would be either useless or actively misleading.
    /// </summary>
    [Fact]
    public void IpRestrictionIsOffByDefault() =>
        Assert.True(new WebhookVerifier(TestSupport.MakeConfig()).Accepts(TestSupport.Secret, "8.8.8.8"));
}

public class ConfigValidationTests
{
    [Fact]
    public void AMissingOrShortWebhookSecretIsRefused()
    {
        foreach (var secret in new[] { "", "x" })
        {
            Assert.Throws<ConfigurationException>(() => TestSupport.MakeConfig(webhookSecret: secret));
        }
    }

    [Fact]
    public void AMissingOrShortPepperIsRefused()
    {
        foreach (var pepper in new[] { "", "too-short" })
        {
            Assert.Throws<ConfigurationException>(() => TestSupport.MakeConfig(hashPepper: pepper));
        }
    }

    [Fact]
    public void AMalformedBotTokenIsRefused() =>
        Assert.Throws<ConfigurationException>(() => TestSupport.MakeConfig(botToken: "not-a-token"));

    [Fact]
    public void ABotUsernameWithAnAtSignIsRefused() =>
        Assert.Throws<ConfigurationException>(() => TestSupport.MakeConfig(botUsername: "@kampe_test_bot"));

    [Theory]
    [InlineData("maxAttempts", 0)]
    [InlineData("maxAttempts", 1000)]
    [InlineData("codeTtl", 86400)]
    [InlineData("cooldown", 0)]
    [InlineData("linkCodeLength", 6)]
    [InlineData("codeLength", 4)]
    public void OutOfRangeNumbersAreRefused(string field, int value)
    {
        Assert.Throws<ConfigurationException>(() => field switch
        {
            "maxAttempts" => TestSupport.MakeConfig(maxAttempts: value),
            "codeTtl" => TestSupport.MakeConfig(codeTtl: value),
            "cooldown" => TestSupport.MakeConfig(cooldown: value),
            "linkCodeLength" => TestSupport.MakeConfig(linkCodeLength: value),
            "codeLength" => TestSupport.MakeConfig(codeLength: value),
            _ => throw new InvalidOperationException(field),
        });
    }

    [Fact]
    public void AnEmptyOnDemandAllowlistIsRefused() =>
        Assert.Throws<ConfigurationException>(() =>
            TestSupport.MakeConfig(onDemandSatisfies: Array.Empty<string>()));

    /// <summary>
    /// A lenient parse would read "5 attempts" as 5 and "nonsense" as 0, turning a
    /// typo in the environment into a silently wrong security parameter.
    /// </summary>
    [Fact]
    public void FromEnvironmentRejectsANonNumericValue()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["TELEGRAM_BOT_TOKEN"] = "123456789:AAFakeTokenForTestsOnly_0123456789abc",
            ["TELEGRAM_WEBHOOK_SECRET"] = TestSupport.Secret,
            ["TELEGRAM_2FA_HASH_PEPPER"] = new string('p', 48),
            ["TELEGRAM_2FA_MAX_ATTEMPTS"] = "5 attempts",
        };

        Assert.Throws<ConfigurationException>(() => Config.FromEnvironment(env));
    }

    [Fact]
    public void FromEnvironmentReadsTheHappyPath()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["TELEGRAM_BOT_TOKEN"] = "123456789:AAFakeTokenForTestsOnly_0123456789abc",
            ["TELEGRAM_WEBHOOK_SECRET"] = TestSupport.Secret,
            ["TELEGRAM_2FA_HASH_PEPPER"] = new string('p', 48),
            ["TELEGRAM_2FA_CODE_TTL"] = "180",
        };

        Assert.Equal(180, Config.FromEnvironment(env).CodeTtl);
    }

    [Fact]
    public void AGeneratedSecretSatisfiesTheValidator() =>
        TestSupport.MakeConfig(webhookSecret: Config.GenerateSecret());
}

public class HandlerTests
{
    private readonly Harness _h = new();
    private readonly UpdateHandler _handler;
    private long _nextUpdate = 1000;

    public HandlerTests() =>
        _handler = new UpdateHandler(
            _h.Service, _h.Config, _h.Store, _h.Telegram, _h.Messages, null, _h.Clock);

    private TelegramUpdate UpdateFor(string text, long chatId = 555000111, string type = "private") =>
        new()
        {
            UpdateId = ++_nextUpdate,
            Message = new TelegramMessage
            {
                MessageId = 1,
                Text = text,
                Chat = new TelegramChat { Id = chatId, Type = type },
            },
        };

    [Fact]
    public async Task StartWithAPayloadLinksTheAccount()
    {
        var request = await _h.Service.StartDeepLinkAsync("user-1");

        await _handler.HandleAsync(UpdateFor($"/start {request.Token}"));

        Assert.True(await _h.Service.IsLinkedAsync("user-1"));
        Assert.Contains("second factor", _h.Telegram.LastMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CodeIssuesACodeForALinkedChat()
    {
        _h.Seed();
        await _handler.HandleAsync(UpdateFor("/code"));

        Assert.Matches("^[0-9]{6}$", _h.LastCode);
    }

    [Fact]
    public async Task CodeTellsAnUnlinkedChatHowToLink()
    {
        await _handler.HandleAsync(UpdateFor("/code"));

        Assert.Contains("not linked", _h.Telegram.LastMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CodeInsideTheCooldownExplainsTheWait()
    {
        _h.Seed();
        await _handler.HandleAsync(UpdateFor("/code"));
        await _handler.HandleAsync(UpdateFor("/code"));

        Assert.Contains("just sent", _h.Telegram.LastMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARepeatedUpdateIdIsDropped()
    {
        _h.Seed();
        var update = UpdateFor("/code");

        Assert.True(await _handler.HandleAsync(update));
        Assert.False(await _handler.HandleAsync(update));
        Assert.Single(_h.Telegram.Sent);
    }

    /// <summary>
    /// An update marked done before its work succeeds is an update permanently
    /// lost: the retry arrives, sees the marker, and drops it.
    /// </summary>
    [Fact]
    public async Task TheClaimIsReleasedWhenHandlingFails()
    {
        _h.Seed();
        _handler.On("boom", (_, _) => throw new InvalidOperationException("downstream failure"));
        var update = UpdateFor("/boom");

        await Assert.ThrowsAsync<InvalidOperationException>(() => _handler.HandleAsync(update));

        var retried = false;
        _handler.On("boom", (_, _) =>
        {
            retried = true;

            return Task.CompletedTask;
        });

        await _handler.HandleAsync(update);

        Assert.True(retried, "Telegram's retry must be processed");
    }

    /// <summary>Otherwise the bot hands out verification codes in front of every member.</summary>
    [Fact]
    public async Task GroupChatsAreIgnored()
    {
        _h.Seed("user-1", "-1001234567890");

        await _handler.HandleAsync(UpdateFor("/code", -1001234567890, "supergroup"));

        Assert.Empty(_h.Telegram.Sent);
    }

    /// <summary>Codes travel application-to-user, never user-to-bot.</summary>
    [Fact]
    public async Task FreeTextIsNotTreatedAsACode()
    {
        _h.Seed();
        await _handler.HandleAsync(UpdateFor("123456"));

        Assert.Contains("do not know that command", _h.Telegram.LastMessage, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACommandAddressedToTheBotIsUnderstood()
    {
        _h.Seed();
        await _handler.HandleAsync(UpdateFor("/code@kampe_test_bot"));

        Assert.Matches("^[0-9]{6}$", _h.LastCode);
    }

    /// <summary>
    /// Whoever holds the phone can already read the codes; letting them also remove
    /// the factor turns a stolen phone into a single-factor account.
    /// </summary>
    [Fact]
    public async Task UnlinkAnswersWithInstructionsAndDoesNotUnlink()
    {
        _h.Seed();
        await _handler.HandleAsync(UpdateFor("/unlink"));

        Assert.Contains("cannot be done from the chat", _h.Telegram.LastMessage, StringComparison.Ordinal);
        Assert.True(await _h.Service.IsLinkedAsync("user-1"));
    }

    [Fact]
    public async Task AnApplicationCommandCanBeRegistered()
    {
        (string ChatId, string Argument)? seen = null;

        _handler.On("balance", (chatId, argument) =>
        {
            seen = (chatId, argument);

            return Task.CompletedTask;
        });

        await _handler.HandleAsync(UpdateFor("/balance usd"));

        Assert.Equal(("555000111", "usd"), seen);
    }

    [Fact]
    public async Task ACallbackQueryIsAcknowledgedThenHandled()
    {
        _h.Seed();

        await _handler.HandleAsync(new TelegramUpdate
        {
            UpdateId = 991,
            CallbackQuery = new TelegramCallbackQuery
            {
                Id = "cb-1",
                Data = "code",
                Message = new TelegramMessage
                {
                    Chat = new TelegramChat { Id = 555000111, Type = "private" },
                },
            },
        });

        Assert.Equal(new[] { "cb-1" }, _h.Telegram.Answered.ToArray());
        Assert.Matches("^[0-9]{6}$", _h.LastCode);
    }

    [Fact]
    public async Task AnUpdateWithNoMessageIsIgnored()
    {
        Assert.False(await _handler.HandleAsync(new TelegramUpdate { UpdateId = 1 }));
        Assert.Empty(_h.Telegram.Sent);
    }

    /// <summary>
    /// A chat id arrives as a JSON number from Telegram and as a string from a
    /// hand-written test or another implementation.
    /// </summary>
    [Fact]
    public async Task AChatIdIsReadAsEitherANumberOrAString()
    {
        _h.Seed();

        Assert.True(await _handler.HandleJsonAsync(
            """{"update_id":5001,"message":{"message_id":1,"text":"/code","chat":{"id":555000111,"type":"private"}}}"""));

        ((FrozenClock)_h.Clock).Advance(121);

        Assert.True(await _handler.HandleJsonAsync(
            """{"update_id":5002,"message":{"message_id":2,"text":"/code","chat":{"id":"555000111","type":"private"}}}"""));

        Assert.Equal(2, _h.Telegram.Sent.Count);
    }

    /// <summary>
    /// A malformed body on a public endpoint is something to answer 200 to and
    /// ignore, not something to turn into a 500 Telegram will retry forever.
    /// </summary>
    [Fact]
    public async Task AMalformedBodyIsIgnoredRatherThanThrown()
    {
        Assert.False(await _handler.HandleJsonAsync("not json at all"));
        Assert.Empty(_h.Telegram.Sent);
    }
}
