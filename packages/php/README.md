# kampe/telegram-2fa

Telegram as a second authentication factor for PHP 8.1+. Framework-agnostic core,
with a Laravel adapter included and no required dependencies.

Implements [SPEC.md](../../SPEC.md) v1.0. The
[Node package](../node) in the same repository implements the same protocol, so
both can run against one bot and one database.

```bash
composer require kampe/telegram-2fa
```

---

## Laravel

Auto-discovered. Publish, migrate, configure:

```bash
php artisan vendor:publish --tag=telegram-2fa-config
php artisan vendor:publish --tag=telegram-2fa-migrations
php artisan migrate

php artisan telegram:webhook --generate-secret   # → .env
php artisan telegram:webhook                     # register with Telegram
php artisan telegram:status                      # verify the wiring
```

```php
use Kampe\TelegramTwoFactor\Laravel\HasTelegramTwoFactor;

class User extends Authenticatable
{
    use HasTelegramTwoFactor;
}
```

```php
$link   = $user->startTelegramLink();                       // → ->url for a t.me button
$result = $user->completeTelegramLink($pastedCode);         // paste flow
$sent   = $user->sendTelegramCode('withdrawal');            // challenge
$check  = $user->verifyTelegramCode($code, 'withdrawal');   // verification
$moved  = $user->replaceTelegramChat($code);                // move to a new account
$gone   = $user->unlinkTelegram($code);                     // requires proof
```

Full controller, route and view code: [examples/laravel](../../examples/laravel).

---

## Any other framework

Construct the service with four adapters. Nothing below touches a framework.

```php
use Kampe\TelegramTwoFactor\{Config, TelegramTwoFactor};
use Kampe\TelegramTwoFactor\Telegram\{DefaultMessages, HttpTelegramClient};

$config = Config::fromArray([
    'bot_token' => getenv('TELEGRAM_BOT_TOKEN'),
    'bot_username' => getenv('TELEGRAM_BOT_USERNAME'),
    'webhook_secret' => getenv('TELEGRAM_WEBHOOK_SECRET'),
    'hash_pepper' => getenv('TELEGRAM_2FA_HASH_PEPPER'),
    'app_name' => 'Kampe',
]);

$tfa = new TelegramTwoFactor(
    $config,
    new MyRedisCodeStore($redis),     // Contracts\CodeStore     — 3 methods
    new MyUserIdentityStore($pdo),    // Contracts\IdentityStore — 4 methods
    new HttpTelegramClient($config->botToken),
    new DefaultMessages(),
);
```

`Config` validates on construction and throws `ConfigurationError` rather than
accepting a configuration that cannot be secure — a missing webhook secret, an
unlimited attempt budget, a code lifetime measured in days.

### The webhook

Two lines before anything else happens:

```php
use Kampe\TelegramTwoFactor\Webhook\{UpdateHandler, WebhookVerifier};

$verifier = new WebhookVerifier($config);

if (! $verifier->accepts($_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] ?? null)) {
    http_response_code(403);
    exit;
}

$handler = new UpdateHandler($tfa, $config, $store, $telegram, new DefaultMessages());
$handler->handle(json_decode(file_get_contents('php://input'), true) ?? []);

http_response_code(200);    // always 200 — see SPEC.md 7.5
echo '{"ok":true}';
```

Skipping the verifier makes the endpoint accept "this chat id is asking for a
code" from anyone who finds the URL. See
[SECURITY.md T1](../../SECURITY.md#t1--a-forged-webhook-request).

### Adding your own bot commands

```php
$handler->on('balance', function (string $chatId, string $argument) use ($telegram) {
    $telegram->sendMessage($chatId, 'Balance: ...');
});
```

---

## API

### Linking

| Method | Purpose |
| --- | --- |
| `startDeepLink(string $userId): LinkRequest` | Mint a nonce bound to the account; `->url` is the `t.me` link. |
| `completeDeepLink(string $token, string $chatId): LinkResult` | Resolve a `/start` payload. Single use. |
| `startPasteLink(string $chatId): LinkRequest` | Bot side: mint an 8-character code bound to the chat. |
| `completePasteLink(string $userId, string $code): LinkResult` | Authenticated page side. Rate-limit this. |
| `startChatReplacement(string $userId, string $code): LinkRequest\|VerificationResult` | Move to a new Telegram account, proving the old one first. |

### Challenge and verification

| Method | Purpose |
| --- | --- |
| `push(string $userId, string $purpose = 'login'): ChallengeResult` | Issue a code and send it. |
| `pull(string $chatId): ChallengeResult` | The user asked the bot for one; purpose `on_demand`. |
| `verify(string $userId, string $code, string $purpose = 'login'): VerificationResult` | Check a code. |

Neither challenge method returns the code, so both results are safe to serialise
into an HTTP response.

`$purpose` names the step a code authorises and is checked on every
verification. Pass the action's own name for anything privileged:

```php
$user->sendTelegramCode('withdrawal');
// ...
$user->verifyTelegramCode($code, 'withdrawal');   // a login code will not pass
```

There is no "match anything" value, and the default is `login` on both sides
rather than a wildcard. The constants are
`TelegramTwoFactor::PURPOSE_LOGIN`, `PURPOSE_ON_DEMAND`, `PURPOSE_REPLACE` and
`PURPOSE_UNLINK`; a code the user fetched with `/code` carries `on_demand` and
satisfies any purpose, which is what keeps `/code` usable for confirming an
unlink.

### State and removal

| Method | Purpose |
| --- | --- |
| `isLinked(string $userId): bool` | Verified link present. |
| `identity(string $userId): ?Identity` | The binding, if any. |
| `identityForChat(string $chatId): ?Identity` | Reverse lookup, for the webhook. |
| `unlink(string $userId, string $code): VerificationResult` | Remove, with proof under purpose `unlink`. |
| `unlinkAfterExternalProof(string $userId, string $reason): bool` | Remove, when another factor proved it. |

Errors are the `ErrorCode` enum, whose values are the protocol's shared strings
(`not_linked`, `cooldown`, `invalid`, …). `$error->message()` gives text safe to
show a user.

---

## Contracts

| Interface | Methods | Bundled implementations |
| --- | --- | --- |
| `CodeStore` | `get`, `put`, `forget` | `Stores\ArrayCodeStore`, `Laravel\CacheCodeStore` |
| `IdentityStore` | `findByUserId`, `findByChatId`, `link`, `unlink` | `Stores\ArrayIdentityStore`, `Laravel\EloquentIdentityStore` |
| `TelegramClient` | `sendMessage`, `answerCallbackQuery`, `getMe`, `setWebhook`, `deleteWebhook` | `Telegram\HttpTelegramClient` (curl) |
| `Messages` | 10 string methods | `Telegram\DefaultMessages` (English) |
| `Clock` | `now` | `Support\SystemClock`, `Support\FrozenClock` |
| `Logger` | `info`, `warning`, `error` | `Support\NullLogger`, `Support\PsrLogger` |

`FrozenClock` ships in `src` rather than `tests` so your own suite can test
expiry and cooldown without sleeping through them.

---

## Configuration

Defaults are the recommended values; the bounds are enforced.

| Key | Default | Bounds |
| --- | --- | --- |
| `code_length` | 6 | 6–8 |
| `code_ttl` | 300 | 30–600 |
| `cooldown` | 120 | ≥ 30 |
| `max_attempts` | 5 | 1–10 |
| `link_code_length` | 8 | ≥ 8 |
| `link_ttl` | 600 | 60–900 |
| `webhook_secret` | — | 32–256 chars of `A-Za-z0-9_-`, required |
| `hash_pepper` | `''` | any; strongly recommended |
| `dedupe_updates` | `true` | — |
| `restrict_webhook_ips` | `false` | — |

---

## Requirements

PHP 8.1 or newer. `ext-curl` for the bundled Telegram client; implement
`TelegramClient` yourself to avoid it.

## Tests

```bash
composer install
composer test
```

73 tests written clause by clause against the specification.
