<div align="center">

# Telegram 2FA

**Telegram as a second authentication factor — specified once, implemented in PHP and Node.**

[![Spec](https://img.shields.io/badge/spec-v1.0-informational)](SPEC.md)
[![PHP](https://img.shields.io/badge/php-%E2%89%A58.1-777bb4)](packages/php)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-5fa04e)](packages/node)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Part of the [Kampe](https://getkampe.com) ecosystem.

</div>

---

Most applications that need a second factor reach for SMS, which costs money per
message, leaks through SIM swaps, and arrives late or not at all on some networks.
A Telegram bot is free, instant, end-to-end over TLS, and already installed on the
phone of a large part of the world.

This repository is that second factor done properly: **one protocol
specification** and **two reference implementations** that interoperate with the
same bot, the same storage layout and the same security properties.

```
telegram-2fa/
├── SPEC.md              the protocol — normative, language-neutral
├── SECURITY.md          threat model, and the mistakes this design rules out
├── packages/php/        kampe/telegram-2fa        — PHP 8.1+, Laravel adapter
├── packages/node/       @kampe/telegram-2fa       — Node 18+, TypeScript
├── examples/            Laravel and Express wiring, end to end
└── docs/                bot setup, flows, porting to other languages
```

If your language is not here, implement [SPEC.md](SPEC.md) — it is written to be
ported, and [docs/porting.md](docs/porting.md) is the checklist.

---

## What it does

Three things, each with a reason to exist.

**Linking.** Binds one Telegram chat to one account, through a `t.me` deeplink the
user taps, or a short code they copy from the bot into your settings page. Moving
to a new Telegram account is its own flow, and costs a code from the old one.

**Challenge.** Issues a one-time code and delivers it to that chat — either pushed
by your application at the moment it needs one, or pulled by the user sending
`/code` to the bot when they would rather not wait.

**Verification.** Checks a submitted code: hashed, constant-time, single-use,
attempt-budgeted, bound to the step it was issued for, with a cooldown between
sends.

And one more, because it is the step attackers actually use: **unlinking**
requires proof of the factor being removed, not just a logged-in session.

---

## Quick start

### PHP

```bash
composer require kampe/telegram-2fa
```

On Laravel, publish and migrate:

```bash
php artisan vendor:publish --tag=telegram-2fa-config
php artisan vendor:publish --tag=telegram-2fa-migrations
php artisan migrate
```

Then in `.env`:

```dotenv
TELEGRAM_BOT_TOKEN=123456789:AA...        # from @BotFather
TELEGRAM_BOT_USERNAME=your_bot            # no @
TELEGRAM_WEBHOOK_SECRET=                  # php artisan telegram:webhook --generate-secret
TELEGRAM_2FA_HASH_PEPPER=                  # any long random string
```

Register the webhook and check the wiring:

```bash
php artisan telegram:webhook
php artisan telegram:status
```

Add the trait to your user model and you have the whole flow:

```php
use Kampe\TelegramTwoFactor\Laravel\HasTelegramTwoFactor;

class User extends Authenticatable
{
    use HasTelegramTwoFactor;
}
```

```php
// Linking: show this URL as a button, and as a QR code for desktop users whose
// Telegram is on their phone. Any QR library will do — the package does not
// ship one, because $link->url is an ordinary string.
$link = $user->startTelegramLink();
return view('settings.telegram', ['url' => $link->url]);

// Challenge, at the moment you need one. The purpose names the step.
$result = $user->sendTelegramCode(purpose: 'withdrawal');

if (! $result->ok) {
    return back()->withErrors($result->error->message());
}

// Verification. The purpose must match what the code was issued for, so a code
// sent to confirm a sign-in cannot approve a payout.
$check = $user->verifyTelegramCode($request->code, purpose: 'withdrawal');

if (! $check->ok) {
    return back()->withErrors($check->error->message());
}
```

Not on Laravel? The core has no framework in it — construct
`Kampe\TelegramTwoFactor\TelegramTwoFactor` with your own four adapters. See
[packages/php/README.md](packages/php/README.md).

### Node

```bash
npm install @kampe/telegram-2fa
```

```ts
import {
  Config,
  DefaultMessages,
  FetchTelegramClient,
  RedisCodeStore,
  TelegramTwoFactor,
} from '@kampe/telegram-2fa'

const tfa = new TelegramTwoFactor({
  config: Config.fromEnv(),
  store: new RedisCodeStore(redis),
  identities: myIdentityStore,              // 4 methods, see contracts.ts
  telegram: new FetchTelegramClient({ botToken: process.env.TELEGRAM_BOT_TOKEN! }),
  messages: new DefaultMessages(),
})

// Linking
const { url } = await tfa.startDeepLink(user.id)

// Challenge
const sent = await tfa.push(user.id, 'withdrawal')

// Verification — the purpose must match, so a sign-in code cannot approve this
const check = await tfa.verify(user.id, submittedCode, 'withdrawal')
```

The webhook, with the check that matters:

```ts
app.post('/telegram/webhook', express.json(), async (req, res) => {
  if (!verifier.accepts(req.get(SECRET_HEADER), req.ip)) {
    return res.sendStatus(403)
  }

  await handler.handle(req.body)
  res.json({ ok: true })        // always 200 — see SPEC.md 7.5
})
```

Full wiring in [examples/express](examples/express).

---

## The design, in six decisions

Each of these is a place where the obvious implementation is wrong in a way that
still passes a manual test. They are specified in [SPEC.md](SPEC.md) and argued in
[SECURITY.md](SECURITY.md).

**1. The webhook authenticates every request.** Telegram will send a
`secret_token` of your choosing in a header on every update. Without checking it,
your webhook is a public endpoint that accepts "this chat id is asking for a
code" from anyone who finds the URL — and the code then arrives in the real
owner's chat, so nothing in your application looks wrong. The secret is
mandatory in both packages: a configuration without one is refused at startup
rather than warned about.

**2. Codes are stored hashed and compared in constant time.** A fast HMAC, not a
password KDF — these codes live for minutes and are attempt-budgeted, so the hash
is there to make a dumped cache or a leaked log useless, not to resist cracking.
Comparison is `hash_equals` / `timingSafeEqual`, because `==` on two
numeric-looking strings in PHP compares them as numbers.

**3. Nothing ever logs a code.** Not the code, not the link token, not the raw
update body — and the update body is where the codes are, which is why logging
the whole payload at `info` is the most common way a 2FA implementation leaks
every code it has ever sent.

**4. One code, one key, one use, five attempts, one purpose.** Both challenge
directions write the same store key, so either satisfies one verification; an
implementation that writes one key and reads another appears to work while every
pushed code silently fails. A verified code is deleted. A wrong guess spends one
of five attempts and does **not** extend the code's life. And a code is bound to
the step it was issued for, with no way to skip that check by omitting the
argument — a default of "compare against nothing" means the binding does nothing
unless every call site opts in, and the call site that forgets is the one that
matters.

**5. One chat is the factor for exactly one account** — enforced by a unique
index, not only by an application check, because two concurrent links both pass
the check and only one can pass the index.

**6. Removing the factor requires the factor.** Unlinking from a logged-in
session alone is exactly the move an attacker with a stolen session makes.

---

## Status

The protocol is at version 1.0 and both packages implement it in full. The test
suites are written clause by clause against the specification and are its
executable form — `composer test` in `packages/php`, `npm test` in
`packages/node`.

## Licence

[MIT](LICENSE) © Joseph Uruetse
