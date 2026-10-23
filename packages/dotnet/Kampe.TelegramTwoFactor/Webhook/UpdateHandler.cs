using System.Globalization;

namespace Kampe.TelegramTwoFactor.Webhook;

/// <summary>
/// Turns a verified update into protocol actions.
/// </summary>
/// <remarks>
/// Framework-free: hand it a parsed update and it does the work. Routing, body
/// parsing and the secret-token check belong to the caller.
/// <para>
/// Commands: /start (with or without a deeplink payload), /code, /status, /link,
/// /unlink, /help. Anything else gets a short reply rather than silence, because
/// silence from a security bot reads as a broken security bot.
/// </para>
/// </remarks>
public sealed class UpdateHandler
{
    private readonly TelegramTwoFactorService _service;
    private readonly Config _config;
    private readonly ICodeStore _store;
    private readonly ITelegramClient _telegram;
    private readonly IMessages _messages;
    private readonly IEventLog _log;
    private readonly IClock _clock;
    private readonly Func<string, string>? _accountLabel;
    private readonly Dictionary<string, Func<string, string, CancellationToken, Task>> _extra =
        new(StringComparer.Ordinal);

    /// <summary>Creates the handler.</summary>
    public UpdateHandler(
        TelegramTwoFactorService service,
        Config config,
        ICodeStore store,
        ITelegramClient telegram,
        IMessages messages,
        IEventLog? log = null,
        IClock? clock = null,
        Func<string, string>? accountLabel = null)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _telegram = telegram ?? throw new ArgumentNullException(nameof(telegram));
        _messages = messages ?? throw new ArgumentNullException(nameof(messages));
        _log = log ?? NullEventLog.Instance;
        _clock = clock ?? new SystemClock();
        _accountLabel = accountLabel;
    }

    /// <summary>
    /// Registers an application command, for example /balance.
    /// </summary>
    /// <remarks>
    /// The handler runs only after the update has been verified as coming from
    /// Telegram, but the argument is still user input: treat it as such.
    /// </remarks>
    public UpdateHandler On(string command, Func<string, string, CancellationToken, Task> handler)
    {
        _extra[Normalise(command)] = handler ?? throw new ArgumentNullException(nameof(handler));

        return this;
    }

    /// <summary>Registers an application command that needs no cancellation token.</summary>
    public UpdateHandler On(string command, Func<string, string, Task> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        return On(command, (chatId, argument, _) => handler(chatId, argument));
    }

    /// <summary>Parses and handles a raw update body.</summary>
    public Task<bool> HandleJsonAsync(string json, CancellationToken ct = default)
    {
        var update = TelegramUpdate.Parse(json);

        return update is null ? Task.FromResult(false) : HandleAsync(update, ct);
    }

    /// <summary>
    /// Handles one update.
    /// </summary>
    /// <returns>Whether the update was acted on.</returns>
    /// <remarks>
    /// Either way the caller should answer 200: a non-2xx makes Telegram retry and
    /// queue every later update behind this one.
    /// </remarks>
    public async Task<bool> HandleAsync(TelegramUpdate update, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(update);

        var claim = await ClaimAsync(update, ct).ConfigureAwait(false);

        if (claim.Duplicate)
        {
            return false;
        }

        bool handled;

        try
        {
            handled = await DispatchAsync(update, ct).ConfigureAwait(false);
        }
        catch
        {
            // Release the claim so Telegram's retry is processed rather than discarded
            // as a duplicate. Marking an update done before its work succeeds turns
            // one transient failure into a permanently lost operation.
            if (claim.Key is not null)
            {
                await _store.ForgetAsync(claim.Key, ct).ConfigureAwait(false);
            }

            throw;
        }

        // Only now is it really handled, so hold the claim for the full window.
        if (claim.Key is not null)
        {
            await _store.PutAsync(claim.Key, "\"done\"", _config.UpdateDedupeTtl, ct).ConfigureAwait(false);
        }

        return handled;
    }

    private async Task<bool> DispatchAsync(TelegramUpdate update, CancellationToken ct)
    {
        if (update.CallbackQuery is not null)
        {
            return await HandleCallbackAsync(update.CallbackQuery, ct).ConfigureAwait(false);
        }

        var message = update.Message;

        if (message?.Chat?.ChatId is null || message.Text is null)
        {
            return false;
        }

        var chatId = message.Chat.ChatId;
        var text = message.Text.Trim();

        if (text.Length == 0)
        {
            return false;
        }

        // Private chats only. A bot added to a group would otherwise hand out
        // verification codes in front of every member of it.
        if ((message.Chat.Type ?? "private") != "private")
        {
            return false;
        }

        if (!text.StartsWith('/'))
        {
            // Codes travel application-to-user, never user-to-bot, so free text is not
            // a code to check. Nudging rather than parsing also means a user who
            // pastes a code into the wrong window has not handed it to the bot.
            await _telegram.SendMessageAsync(chatId, _messages.UnknownCommand(), null, ct).ConfigureAwait(false);

            return false;
        }

        var (command, argument) = ParseCommand(text);

        _log.Info(
            "telegram-2fa: command",
            new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["command"] = command,
                ["update_id"] = update.UpdateId,
            });

        return command switch
        {
            "start" => await StartAsync(chatId, argument, ct).ConfigureAwait(false),
            "code" or "otp" or "2fa" => await SendCodeAsync(chatId, ct).ConfigureAwait(false),
            "status" => await StatusAsync(chatId, ct).ConfigureAwait(false),
            "link" => await LinkAsync(chatId, ct).ConfigureAwait(false),
            "unlink" => await UnlinkHintAsync(chatId, ct).ConfigureAwait(false),
            "help" => await HelpAsync(chatId, ct).ConfigureAwait(false),
            _ => await DispatchExtraAsync(command, chatId, argument, ct).ConfigureAwait(false),
        };
    }

    private async Task<bool> StartAsync(string chatId, string payload, CancellationToken ct)
    {
        if (payload.Length == 0)
        {
            return await HelpAsync(chatId, ct).ConfigureAwait(false);
        }

        var result = await _service.CompleteDeepLinkAsync(payload, chatId, ct).ConfigureAwait(false);

        if (result.Ok && result.Identity is not null)
        {
            var label = _accountLabel is null ? "your account" : _accountLabel(result.Identity.UserId);

            await _telegram.SendMessageAsync(
                chatId, _messages.LinkSucceeded(label, _config.AppName), null, ct).ConfigureAwait(false);

            return true;
        }

        await _telegram.SendMessageAsync(
            chatId,
            result.Error == ErrorCode.AlreadyLinked ? _messages.AlreadyLinked() : _messages.LinkTokenInvalid(),
            null,
            ct).ConfigureAwait(false);

        return false;
    }

    private async Task<bool> LinkAsync(string chatId, CancellationToken ct)
    {
        if ((await _service.IdentityForChatAsync(chatId, ct).ConfigureAwait(false)).IsVerifiedFactor())
        {
            await _telegram.SendMessageAsync(chatId, _messages.AlreadyLinked(), null, ct).ConfigureAwait(false);

            return false;
        }

        var request = await _service.StartPasteLinkAsync(chatId, ct).ConfigureAwait(false);

        await _telegram.SendMessageAsync(
            chatId,
            _messages.LinkInstructions(request.Token, _config.LinkTtl, _config.AppName),
            null,
            ct).ConfigureAwait(false);

        return true;
    }

    private async Task<bool> SendCodeAsync(string chatId, CancellationToken ct)
    {
        // Pull sends the code itself, so the plaintext never reaches here.
        var result = await _service.PullAsync(chatId, Purpose.OnDemand, ct).ConfigureAwait(false);

        if (result.Ok)
        {
            return true;
        }

        var text = result.Error switch
        {
            ErrorCode.NotLinked => _messages.NotLinked(_config.AppName),
            ErrorCode.Cooldown => _messages.Cooldown(result.RetryAfter(_clock.Now)),
            _ => _messages.UnknownCommand(),
        };

        await _telegram.SendMessageAsync(chatId, text, null, ct).ConfigureAwait(false);

        return false;
    }

    private async Task<bool> StatusAsync(string chatId, CancellationToken ct)
    {
        var linked = (await _service.IdentityForChatAsync(chatId, ct).ConfigureAwait(false)).IsVerifiedFactor();

        await _telegram.SendMessageAsync(
            chatId,
            linked ? _messages.Welcome(true, _config.AppName) : _messages.NotLinked(_config.AppName),
            null,
            ct).ConfigureAwait(false);

        return true;
    }

    /// <summary>
    /// /unlink explains where to do it, and does not do it.
    /// </summary>
    /// <remarks>
    /// Whoever holds the phone can already read the codes; letting them also remove
    /// the factor with no session and no password turns a stolen phone into a
    /// permanently single-factor account.
    /// </remarks>
    private async Task<bool> UnlinkHintAsync(string chatId, CancellationToken ct)
    {
        if (!(await _service.IdentityForChatAsync(chatId, ct).ConfigureAwait(false)).IsVerifiedFactor())
        {
            await _telegram.SendMessageAsync(
                chatId, _messages.NotLinked(_config.AppName), null, ct).ConfigureAwait(false);

            return false;
        }

        await _telegram.SendMessageAsync(
            chatId, _messages.UnlinkInstructions(_config.AppName), null, ct).ConfigureAwait(false);

        return true;
    }

    private async Task<bool> HelpAsync(string chatId, CancellationToken ct)
    {
        var linked = (await _service.IdentityForChatAsync(chatId, ct).ConfigureAwait(false)).IsVerifiedFactor();

        await _telegram.SendMessageAsync(
            chatId, _messages.Welcome(linked, _config.AppName), null, ct).ConfigureAwait(false);

        return true;
    }

    private async Task<bool> DispatchExtraAsync(
        string command,
        string chatId,
        string argument,
        CancellationToken ct)
    {
        if (!_extra.TryGetValue(command, out var handler))
        {
            await _telegram.SendMessageAsync(chatId, _messages.UnknownCommand(), null, ct).ConfigureAwait(false);

            return false;
        }

        await handler(chatId, argument, ct).ConfigureAwait(false);

        return true;
    }

    private async Task<bool> HandleCallbackAsync(TelegramCallbackQuery query, CancellationToken ct)
    {
        var id = query.Id ?? string.Empty;

        // Acknowledge first, or the user's client spins for ten seconds.
        if (id.Length > 0)
        {
            await _telegram.AnswerCallbackQueryAsync(id, null, ct).ConfigureAwait(false);
        }

        var chatId = query.Message?.Chat?.ChatId;

        if (chatId is null)
        {
            return false;
        }

        return query.Data switch
        {
            "code" => await SendCodeAsync(chatId, ct).ConfigureAwait(false),
            "status" => await StatusAsync(chatId, ct).ConfigureAwait(false),
            "link" => await LinkAsync(chatId, ct).ConfigureAwait(false),
            "help" => await HelpAsync(chatId, ct).ConfigureAwait(false),
            _ => false,
        };
    }

    private static (string Command, string Argument) ParseCommand(string text)
    {
        var split = text.IndexOf(' ', StringComparison.Ordinal);
        var head = split < 0 ? text : text[..split];
        var tail = split < 0 ? string.Empty : text[(split + 1)..].Trim();
        var command = Normalise(head);

        // In groups Telegram appends the bot name: /code@kampe_bot.
        var at = command.IndexOf('@', StringComparison.Ordinal);

        if (at >= 0)
        {
            command = command[..at];
        }

        return (command, tail);
    }

    private static string Normalise(string command) =>
        command.TrimStart('/').ToLowerInvariant();

    /// <summary>
    /// Claims an update, so exactly one attempt processes it.
    /// </summary>
    /// <remarks>
    /// Telegram retries an update it believes was not delivered, and delivers
    /// concurrently, so the same update_id can arrive more than once and at the same
    /// time. <see cref="ICodeStore.AddAsync"/> is the whole mechanism: checking for a
    /// marker and then writing one is two operations, and two simultaneous deliveries
    /// both find nothing and both proceed.
    /// </remarks>
    private async Task<(string? Key, bool Duplicate)> ClaimAsync(TelegramUpdate update, CancellationToken ct)
    {
        if (!_config.DedupeUpdates || update.UpdateId is null)
        {
            return (null, false);
        }

        var key = _config.Key("update", update.UpdateId.Value.ToString(CultureInfo.InvariantCulture));

        // A short claim, not the full window: if this process dies mid-handling the
        // claim lapses on its own and a later retry can pick the update up.
        var ttl = Math.Max(30, Math.Min(_config.UpdateDedupeTtl, 120));

        if (!await _store.AddAsync(key, "\"claimed\"", ttl, ct).ConfigureAwait(false))
        {
            _log.Info(
                "telegram-2fa: duplicate update dropped",
                new Dictionary<string, object?>(StringComparer.Ordinal) { ["update_id"] = update.UpdateId });

            return (null, true);
        }

        return (key, false);
    }
}
