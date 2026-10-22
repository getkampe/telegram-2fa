# Telegram 2FA — protocol specification

**Version 1.0** · language-neutral · normative

This document defines the Telegram second-factor protocol that the packages in this
repository implement. It exists so that an implementation in any language —
PHP, Node, Python, Go, Rust, Elixir — can interoperate with the same bot, the same
storage schema and the same security properties.

Keywords **MUST**, **MUST NOT**, **SHOULD**, **MAY** follow RFC 2119.

---

## 1. Roles

| Role | Description |
| --- | --- |
| **App** | Your application. Owns user accounts and sessions. Holds the bot token. |
| **Bot** | A Telegram bot, created via [@BotFather](https://t.me/BotFather). |
| **Chat** | A Telegram private chat between one end user and the Bot. Identified by `chat_id`. |
| **Store** | Short-lived key/value storage with TTL (Redis, Memcached, a database table). |
| **Identity store** | Durable storage of the `user_id` to `chat_id` binding (usually your users table). |

The protocol has three phases: **linking**, **challenge**, **verification**, plus **unlinking**.

---

## 2. Identity binding

An account is Telegram-2FA-capable when the Identity store holds a record:

```
{ user_id, chat_id, linked_at }
```

Rules:

1. A `user_id` **MUST** map to at most one `chat_id`.
2. A `chat_id` **MUST** map to at most one `user_id`. Implementations **MUST**
   enforce this with a uniqueness constraint, not only with an application check.
   Without it, one Telegram account can become the second factor for many accounts.
3. `linked_at` **MUST** be set only after the link is proven (section 3). A row with
   a `chat_id` but no `linked_at` is not linked and **MUST NOT** satisfy a challenge.

---

## 3. Linking

Two flows are defined. An implementation **MUST** provide `deeplink` and **MAY**
provide `paste`.

### 3.1 deeplink (preferred)

The App mints the token, so the token is bound to the account before it ever
reaches Telegram.

```
App                         User                    Bot / Webhook
 |                            |                           |
 |-- 1. mint nonce ---------->|                           |
 |   store link:h(nonce)      |                           |
 |     = { user_id }          |                           |
 |   TTL 600s                 |                           |
 |                            |                           |
 |-- 2. t.me/<bot>?start=<nonce> ------------------------->|
 |                            |-- 3. taps link ---------->|
 |                            |                           |
 |<-- 4. webhook: /start <nonce> ------------------------- |
 |   look up link:h(nonce)                                 |
 |   link(user_id, chat_id); delete nonce                  |
 |-- 5. confirmation message ----------------------------->|
```

- The nonce **MUST** be at least 128 bits of cryptographically secure randomness,
  encoded in a Telegram-safe alphabet (`A-Za-z0-9_-`, max 64 bytes for `start`).
- The Store key **MUST** be `link:` plus a hash of the nonce, never the nonce
  itself, so a Store dump does not yield usable link tokens.
- The nonce **MUST** be single-use: deleted on first successful resolution.
- On resolution the App **MUST** re-check that neither the `user_id` nor the
  `chat_id` is already linked, and reject with `already_linked` if either is.

### 3.2 paste

For the case where the user is at a desktop browser and the Telegram client is on a
different device. The Bot mints the code; the user types it into an
**authenticated** page.

```
User                  Bot / Webhook                         App
 |-- /link ----------->|                                     |
 |                     |  code = 8 chars, base32 (Crockford) |
 |                     |  store link:h(code)                 |
 |                     |    = { chat_id }                    |
 |                     |  TTL 600s                           |
 |<-- shows code ------|                                     |
 |                                                           |
 |-- 2. pastes code into signed-in settings page ----------->|
 |                       look up link:h(code)                |
 |                       link(session user_id, chat_id)      |
```

- The code **MUST NOT** be 6 numeric digits. A code in a Store keyed by the code
  alone shares one global namespace with every other outstanding code, so a short
  numeric code is enumerable. Implementations **MUST** use at least 8 characters
  from an alphabet of at least 32 symbols (40 bits or more).
- The paste endpoint **MUST** require an authenticated session and **MUST** be
  rate-limited per session and per IP (section 7).
- The code **MUST** be single-use and **MUST** carry a TTL of no more than 900 s.

### 3.3 Replacing a linked chat

A user who moves to a new Telegram account needs to rebind without losing the
account. An implementation **MUST NOT** let a plain link flow silently move a
verified binding to a different chat (section 2), so replacement is its own
operation in two steps:

1. **Prove the current factor.** The user submits a code from the chat being
   replaced, verified under purpose `replace` (section 5). On success the
   implementation mints a link token as in 3.1, marked `replace` and bound to
   the same `user_id`.
2. **Bind the new chat.** When that token is resolved from a different chat, the
   implementation unlinks the old chat, binds the new one, and **SHOULD** notify
   the old chat that it is no longer a second factor.

The `replace` mark is what authorises the rebinding, and it **MUST** be carried
by the stored token rather than supplied at resolution time — otherwise the step
that proves possession can be skipped by presenting an ordinary token.

A user who has lost access to the old chat entirely cannot complete step 1 and
**MUST** go through the recovery path of section 8 instead.

---

## 4. Challenge

A challenge produces a one-time code that the user will transcribe back into the App.
Two directions are defined; an implementation **SHOULD** support both, and both
**MUST** write to the same Store key so either can satisfy one verification.

### 4.1 push — App sends the code

Used when the App drives the step: login, withdrawal, change of e-mail.

1. The App looks up `chat_id` for `user_id`; absent or unlinked gives `not_linked`.
2. The App checks the cooldown key `cooldown:<user_id>`; present gives `cooldown`,
   together with the time at which another send becomes possible.
3. The App generates the code (section 6).
4. The App writes `code:<user_id>` = `{ hash, expires_at, attempts: 0, purpose }`
   with the code TTL, and `cooldown:<user_id>` with the cooldown TTL.
5. The App sends the code to `chat_id` and returns the expiry and next-send time.

`purpose` names the step the code authorises — `login`, `withdrawal`,
`replace`, whatever the App calls it — and is checked on verification
(section 5). It defaults to `login`.

### 4.2 pull — user asks the Bot

Used when the App cannot reach Telegram at that moment, or when the user prefers it.
The user sends `/code` to the Bot.

1. The webhook resolves `chat_id` to `user_id`; unknown gives a "not linked" reply.
2. Same cooldown check as 4.1.
3. Same generation and same Store key `code:<user_id>`, with purpose `on_demand`.
4. The Bot replies with the code.

A code issued this way carries no knowledge of what the user is about to do with
it, so `on_demand` **MUST** satisfy any requested purpose on verification. This
is the one general-purpose code in the protocol, and it is sound because the user
asked for it deliberately: nothing the App did caused it to exist.

> **The single-key rule.** Both directions write `code:<user_id>`. An implementation
> that writes `code:<user_id>` on push but reads some other key on verify will
> appear to work — the pull path still verifies — while every pushed code silently
> fails, and the failure is invisible in testing if the pull path is the one
> exercised by hand. The spec names one key to make that state unrepresentable.

---

## 5. Verification

`verify(user_id, code, purpose)` returns one of `ok`, `invalid`, `expired`,
`too_many_attempts`. `purpose` defaults to `login`, matching 4.1.

1. Read `code:<user_id>`. Absent gives `expired`.
2. If `attempts >= max_attempts`, give `too_many_attempts` and delete the record.
3. If `now > expires_at`, give `expired` and delete the record.
4. Check the purpose. It is satisfied when the stored purpose equals the
   requested one, or when the stored purpose is `on_demand` (4.2). Otherwise
   treat it as a failed attempt (step 6).
5. Compare `hash(code)` with the stored hash **in constant time**. A plain `==`
   on secret material is a timing oracle, and is also easy to write as a
   type-juggling bug in loosely typed languages.
6. On match: delete the record, return `ok`. The code **MUST** be single-use —
   a code that survives verification can be replayed from a logged request body.
7. On mismatch: increment `attempts`, keep the original TTL, return `invalid`.

The purpose check **MUST NOT** be skippable by omitting the argument. An
implementation whose default is "compare against nothing" provides no binding at
all unless every call site opts in, and the call site that forgets is both
invisible and the one that matters — a code issued to confirm a sign-in
approving a payout. Defaulting to `login` makes the common case correct and
makes a privileged step fail loudly when its purpose was not threaded through.

A failed purpose check **MUST** return `invalid` rather than a distinct error:
telling a caller that a live code exists for a different purpose is information
it has not proved it should have.

`max_attempts` **MUST** default to 5 or fewer. A 6-digit code with unlimited
attempts behind a 10-requests-per-minute throttle is exhausted in about 70 days of
grinding; with 5 attempts per code it is 1 chance in 200 000 per challenge.

---

## 6. Codes

| Property | Requirement |
| --- | --- |
| Source of randomness | Cryptographically secure (`random_int`, `crypto.randomInt`, `crypto/rand`). **MUST NOT** be `rand`, `mt_rand`, `Math.random`. |
| 2FA code format | 6 to 8 characters. Numeric is permitted here because the Store key is `code:<user_id>` — the code is scoped to one account, so the search space is not shared. |
| Link code format | 8 characters or more from an alphabet of 32 symbols or more (section 3.2). |
| Storage | The **hash** of the code (SHA-256 or stronger). The plaintext **MUST NOT** be written to the Store, to a log, to an audit trail or to an error response. |
| TTL | 2FA code 600 s or less. Default 300 s. |
| Cooldown | 60 s or more between sends for one `user_id`. Default 120 s. |

Codes are low-entropy, short-lived and single-use, so a fast hash is correct here;
a password-grade KDF would only add latency. The hash exists to keep a Store or log
dump from yielding live codes, not to resist offline cracking.

---

## 7. Webhook security

The webhook endpoint is a public, unauthenticated URL that is trusted to say
"this chat_id asked for a code". That makes it the most security-sensitive part of
the protocol.

1. **Secret token — required.** The webhook **MUST** be registered with a
   `secret_token`, and every request **MUST** be rejected unless the
   `X-Telegram-Bot-Api-Secret-Token` header matches it in constant time.
   ```
   POST https://api.telegram.org/bot<TOKEN>/setWebhook
     url=https://example.com/telegram/webhook
     secret_token=<32+ random chars from A-Za-z0-9_->
   ```
   Without this, anyone who learns the URL can forge an update carrying any
   `chat_id`, and ask the Bot to mint a code for the account that `chat_id` is
   linked to. It is one header check and it is not optional.
2. **Source range — recommended.** Additionally restrict to Telegram's published
   ranges `149.154.160.0/20` and `91.108.4.0/22`. Behind a proxy this is only
   meaningful if the proxy's `X-Forwarded-For` handling is trusted.
3. **Replies, not reflections.** The webhook **MUST NOT** echo arbitrary user text
   back through a formatted message without escaping it for the chosen parse mode.
4. **Logging.** The webhook **MUST NOT** log the update body verbatim. Updates
   contain message text, which includes the codes themselves, and personal data.
   Log `update_id`, the update kind and the resolved `user_id`.
5. **Always 200.** The webhook **SHOULD** answer `200` for any update it has
   accepted but cannot handle. Telegram retries non-2xx responses with backoff and
   will queue updates behind a failing one.
6. **Idempotency.** `update_id` is unique per update and increases. An
   implementation **SHOULD** drop an `update_id` it has already processed; retries
   after a timeout are normal.

---

## 8. Unlinking

Removing a second factor is a privileged action: it is the step an attacker who has
the session but not the phone needs. Unlinking **MUST** require proof of the factor
being removed, or of an equivalent factor:

1. A current Telegram code (section 5), **or**
2. a code from another enrolled factor (authenticator, SMS, e-mail), **or**
3. an explicit, documented account-recovery path.

On success the implementation **MUST** clear `chat_id`, `linked_at` and any pending
codes, **SHOULD** notify the chat that it is no longer a second factor, and
**SHOULD** write an audit entry.

---

## 9. Store keys

All keys are prefixed with a configurable namespace (default `tg2fa`).

| Key | Value | TTL |
| --- | --- | --- |
| `<ns>:code:<user_id>` | `{ hash, expires_at, attempts, purpose }` | code TTL |
| `<ns>:cooldown:<user_id>` | next-send unix timestamp | cooldown |
| `<ns>:link:<hash(token)>` | `{ user_id }` (deeplink) or `{ chat_id }` (paste), plus `replace: true` for 3.3 | link TTL |
| `<ns>:update:<update_id>` | `1` | retry window or longer |

`user_id` is an opaque string. Implementations **MUST NOT** assume it is an integer.

---

## 10. Error vocabulary

Implementations **MUST** map their failures onto these identifiers, so that a client
can be written once against the protocol rather than against one library.

| Identifier | Meaning |
| --- | --- |
| `not_linked` | The account has no verified Telegram link. |
| `already_linked` | The account, or the chat, is already linked. |
| `cooldown` | A code was sent too recently. Carries `next_send_at`. |
| `send_failed` | Telegram rejected or did not accept the message. |
| `invalid` | The code does not match. |
| `expired` | No live code for this account. |
| `too_many_attempts` | The attempt budget for this code is exhausted. |
| `invalid_token` | Link token unknown, expired or already used. |
| `webhook_unauthorized` | Secret token missing or wrong. |

---

## 11. Conformance

An implementation conforms to this specification when it:

- enforces the uniqueness rules of section 2 at the storage layer;
- implements the deeplink flow of section 3.1, and the replacement flow of 3.3
  with the `replace` mark carried by the stored token;
- writes and reads one key for both challenge directions (section 4);
- checks the purpose on every verification, with no way to skip it by omission,
  and treats `on_demand` as general-purpose (sections 4.2 and 5);
- hashes codes, compares in constant time, and enforces single use and an attempt
  budget (sections 5 and 6);
- rejects webhook requests without a valid secret token (section 7.1);
- never writes a code or a raw update body to a log (sections 6 and 7.4);
- requires proof of a factor before unlinking (section 8);
- uses the key layout of section 9 and the error vocabulary of section 10.

The test suites in `packages/*/test` are written against these clauses and are the
executable form of this document.
