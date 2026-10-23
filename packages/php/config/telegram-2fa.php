<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Bot credentials
    |--------------------------------------------------------------------------
    |
    | Create a bot with @BotFather, then set these in .env. The token is a
    | credential: it can read every message sent to the bot and send as the bot,
    | so it belongs in .env and never in a committed config file or a repo.
    |
    */

    'bot_token' => env('TELEGRAM_BOT_TOKEN', ''),

    // Without the @. Needed to build t.me deeplinks; run
    // `php artisan telegram:status` to read it off the API.
    'bot_username' => env('TELEGRAM_BOT_USERNAME'),

    /*
    |--------------------------------------------------------------------------
    | Webhook secret
    |--------------------------------------------------------------------------
    |
    | 32 to 256 characters of A-Z, a-z, 0-9, underscore or hyphen. Telegram
    | returns it in the X-Telegram-Bot-Api-Secret-Token header on every webhook
    | request, and the package rejects any request where it does not match.
    |
    | It is what stops a stranger posting a forged update to your webhook and
    | asking the bot to mint a 2FA code for somebody else's account. Generate
    | one with `php artisan telegram:webhook --generate-secret`.
    |
    */

    'webhook_secret' => env('TELEGRAM_WEBHOOK_SECRET', ''),

    'webhook_path' => env('TELEGRAM_WEBHOOK_PATH', 'telegram/webhook'),

    // Set to false to register the route yourself. If you do, apply the
    // VerifyTelegramWebhook middleware and exclude the path from CSRF.
    'register_webhook_route' => true,

    /*
    |--------------------------------------------------------------------------
    | Storage
    |--------------------------------------------------------------------------
    |
    | Codes live in Redis. Two requirements, and the second is not a preference:
    |
    | 1. Shared between processes and surviving a deploy. On `array` the store
    |    is per-process and on `file` it is per-server, so a code issued by one
    |    request can be invisible to the next.
    | 2. Real atomic primitives. The package needs an atomic get-and-delete and
    |    an atomic set-if-absent, because single use and the attempt budget are
    |    read-modify-write sequences: without atomicity two simultaneous
    |    verifications of one code can both succeed, and the five-attempt limit
    |    can be beaten by racing it. Laravel's pull() is only atomic where the
    |    driver's own primitive is, which rules out database, file and array.
    |
    | null uses the application default — check what that is before relying
    | on it.
    |
    */

    /*
    | Which adapter stores the codes.
    |
    | 'redis'  The canonical one, and the default. Talks to a Redis connection
    |          directly: values are the JSON of SPEC.md section 9 and single use
    |          rests on one server-side operation, so the PHP, Node, Python, Ruby
    |          and C# implementations can all share one Redis and one bot.
    |
    | 'cache'  Laravel's cache, through CacheCodeStore. Correct for a deployment
    |          where every process touching these keys is PHP, and *only* that:
    |          Laravel's Redis cache serialises values with PHP's serialize(), so
    |          the records are unreadable to the other implementations, and the
    |          take is serialised behind a Laravel named lock that a process in
    |          another language does not take.
    */

    'code_store' => env('TELEGRAM_2FA_CODE_STORE', 'redis'),

    // Which Redis connection, for 'redis'. null uses the application default.
    'redis_connection' => env('TELEGRAM_2FA_REDIS_CONNECTION'),

    /*
    | Acknowledge a connection-level key prefix.
    |
    | A default Laravel application sets options.prefix from REDIS_PREFIX, which
    | defaults to "<app_name>_database_". phpredis prepends it to every key, so
    | the record SPEC.md section 9 calls "tg2fa:code:<user>" is physically stored
    | at "<prefix>tg2fa:code:<user>" — and a Node or Go process looking where the
    | specification says to look finds nothing.
    |
    | The package refuses to start rather than let that happen quietly. Two ways
    | forward:
    |
    | - Give this package a Redis connection with no prefix, and namespace with
    |   key_prefix below instead. Every implementation honours that one.
    | - Set this to true, if every client reading these keys applies the same
    |   prefix — which it does on a PHP-only deployment, where a prefix is
    |   harmless.
    |
    | A serializer or compression setting on the connection is refused outright
    | and cannot be acknowledged: those change the bytes, not the keys, so no
    | other implementation could read the records at all.
    */

    'allow_redis_key_prefix' => env('TELEGRAM_2FA_ALLOW_REDIS_KEY_PREFIX', false),

    // Which cache store, for 'cache'. null uses the application default —
    // check what that is before relying on it.
    'cache_store' => env('TELEGRAM_2FA_CACHE_STORE'),

    'user_model' => env('TELEGRAM_2FA_USER_MODEL', 'App\\Models\\User'),

    'columns' => [
        'chat_id' => 'telegram_chat_id',
        'linked_at' => 'telegram_linked_at',

        // The enrollment generation. It changes on every transition and
        // survives unlinking, so authority over a removed enrollment stays
        // revoked even after the account links again.
        'enrollment' => 'telegram_enrollment',
    ],

    /*
    |--------------------------------------------------------------------------
    | Local cache stores
    |--------------------------------------------------------------------------
    |
    | The package refuses the array and file cache stores, because neither is
    | shared between the processes serving your requests: their data and their
    | locks are local, so one worker cannot see a code another issued, and two
    | workers can verify the same code.
    |
    | Set this to true only for tests or a single-process script.
    |
    */

    'permit_local_cache_store' => false,

    // null uses the application default log channel.
    'log_channel' => env('TELEGRAM_2FA_LOG_CHANNEL'),

    'timeout' => 10,

    'app_name' => env('TELEGRAM_2FA_APP_NAME'),

    /*
    |--------------------------------------------------------------------------
    | Protocol
    |--------------------------------------------------------------------------
    |
    | The knobs defined by SPEC.md. The defaults are the recommended values and
    | the bounds are enforced in Config's constructor, which refuses anything
    | that cannot be secure rather than warning about it.
    |
    */

    'protocol' => [

        // 6 to 8. Six digits is standard and safe here because the attempt
        // budget, not the code length, is what bounds guessing.
        'code_length' => 6,

        // Seconds a code stays valid: 30 to 600.
        'code_ttl' => 300,

        // Minimum seconds between sends for one account, 30 or more. Also
        // rate-limits the bot as a channel for sending someone messages.
        'cooldown' => 120,

        // Wrong guesses allowed per code, 1 to 10. The code dies when the
        // budget is spent, and the user has to request another.
        'max_attempts' => 5,

        // Characters in a paste-flow link code, 8 or more.
        'link_code_length' => 8,

        // Seconds a link token or code stays valid: 60 to 900.
        'link_ttl' => 600,

        // Prefix for every cache key the package writes.
        'key_prefix' => 'tg2fa',

        'hash_algorithm' => 'sha256',

        // Optional pepper for code hashes. With one set, a dumped cache cannot
        // be matched against a precomputed table of all six-digit hashes -
        // which, for six digits, is a table anyone can build in seconds.
        // Changing it invalidates every code in flight, which is harmless.
        'hash_pepper' => env('TELEGRAM_2FA_HASH_PEPPER', ''),

        // Drop repeated update_ids. Telegram retries updates it thinks were
        // not delivered, and a retried /code would otherwise mint a second
        // code and reset the cooldown.
        'dedupe_updates' => true,

        'update_dedupe_ttl' => 3600,

        // Additionally require the request to come from Telegram's published
        // IP ranges. Off by default: behind a proxy or CDN the peer address is
        // the proxy, so this only means something once the proxy is configured
        // as trusted. The secret token is the check that always applies.
        'restrict_webhook_ips' => false,

    ],

];
