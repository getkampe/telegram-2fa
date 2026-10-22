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
{ user_id, chat_id, linked_at, generation }
```

Rules:

1. A `user_id` **MUST** map to at most one `chat_id`.
2. A `chat_id` **MUST** map to at most one `user_id`. Implementations **MUST**
   enforce this with a uniqueness constraint, not only with an application check.
   Without it, one Telegram account can become the second factor for many accounts.
3. `linked_at` **MUST** be set only after the link is proven (section 3). A row with
   a `chat_id` but no `linked_at` is not linked and **MUST NOT** satisfy a challenge.

### 2.1 The enrollment generation

`generation` identifies one enrollment of one account. Anything holding authority
over an enrollment — a pending replacement token, a challenge in flight —
records it, and is refused once it differs.

1. It **MUST** change on every transition: linking, replacement, unlinking and
   recovery.
2. It **MUST** be a persistent monotonic counter or at least 128 bits of
   cryptographically secure randomness. It **MUST NOT** be derived from the
   values it exists to distinguish: a digest of `chat_id` and `linked_at`
   repeats when the same chat is unlinked and relinked within the resolution of
   `linked_at`, reviving every token minted before the unlink.
3. It **MUST** survive the unlinked state. Were it cleared on unlink, a token
   minted beforehand would become valid again the moment the account linked
   again — so the row persists carrying a generation, no `chat_id` and no
   `linked_at`.

### 2.2 Transitions are conditional

Every change of enrollment state **MUST** be a single compare-and-set against
the generation the caller expects:

```
transition(user_id, chat_id|null, expected_generation, next_generation)
  -> the new state, or nothing when expected_generation is not current
```

A failed expectation **MUST** leave the stored record exactly as it was.

Read-then-write cannot express this. Validating a token and then writing the
binding leaves a window in which a recovery, an unlink or a competing link can
land, and the write then applies to an enrollment the caller never checked —
which is precisely how a replacement token outlives the enrollment it proved.
The comparison and the write must be one operation: `UPDATE ... WHERE
generation = ?` with an affected-row count, a transaction, or an equivalent.

Recovery paths **MAY** transition unconditionally, since the caller has already
proved identity by other means and must not be blocked by concurrent change.

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

**Replacement is destination-safe.** The existing binding **MUST NOT** be
released before the new one is known to be available. An implementation that
unlinks the old chat and then discovers the destination belongs to another
account has destroyed the user's second factor as a side effect of a request
that failed — leaving the account either locked out or protected by one factor,
neither of which the user asked for. The move **MUST** therefore be a single
write that either takes the new binding or leaves the old one untouched, and the
old chat **MUST NOT** be told it has been unlinked until the move has succeeded.

**The recorded generation is the one that was proved.** An implementation
**MUST** capture the generation before verifying the code and record that value,
and **MUST NOT** substitute a generation read after verification. A recovery
landing in that window carries its own new generation, and recording it grants
the token authority over an enrollment the user never proved. An implementation
**MUST** also refuse to issue the token at all if the enrollment changed while
the code was being verified.

**Replacement authority does not survive its enrollment.** The token **MUST**
record the `generation` it proved (section 2.1), and that value **MUST** be the
expectation of the conditional transition that performs the rebinding (section
2.2) — not merely checked beforehand. Storing only the `user_id` and the
`replace` mark is not enough: a token minted before an account recovery would
still be honoured after it, so whoever held that token could move the factor to
a chat of their choosing the moment the user finished recovering. Checking the
generation and *then* writing is also not enough, because a recovery can land
between the two.

**Replacement invalidates codes in flight.** Any challenge outstanding for the
account **MUST** be dropped when the binding moves, along with the cooldown. A
code already delivered to the old chat is proof in the hands of whoever still
holds that chat; dropping the cooldown is a convenience, so that the user can be
challenged on the new chat immediately.

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
4. The App writes `code:<user_id>` with the code TTL, carrying the enrollment
   `generation` it was issued against and a random `challenge_id`, and
   `cooldown:<user_id>` with the cooldown TTL.
5. The App sends the code to `chat_id` and returns the expiry and next-send time.
6. If delivery fails, the App **MUST** drop the challenge **conditionally** — only
   when the stored `challenge_id` is still the one it issued. An unconditional
   delete throws away a newer challenge whenever a slow send outlasts the
   cooldown, which takes a code out of the user's hands after they were told to
   expect it.

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
4. Check the enrollment. The record's `generation` **MUST** equal the account's
   current one, or the challenge belongs to an enrollment that has since been
   replaced, unlinked or recovered; report `expired` and do not restore it.
5. Check the purpose. It is satisfied when the stored purpose equals the
   requested one, or when the stored purpose is `on_demand` (4.2). Otherwise
   treat it as a failed attempt (final step).
6. Compare `hash(code)` with the stored hash **in constant time**. A plain `==`
   on secret material is a timing oracle, and is also easy to write as a
   type-juggling bug in loosely typed languages.
7. On match: delete the record, return `ok`. The code **MUST** be single-use —
   a code that survives verification can be replayed from a logged request body.
8. On mismatch: increment `attempts`, keep the original TTL, return `invalid`.

Step 4 is what makes revocation sound, and it is deliberately the *acceptance*
check rather than a cleanup. Clearing challenges when an enrollment changes
(section 3.3) races a verification that has already taken the record and is
about to write it back; that race cannot be closed from either side. So an
implementation **MUST** re-check the generation before accepting, and **SHOULD**
re-check it before restoring a failed attempt. The guarantee is that a
resurrected record is inert, not that resurrection is impossible — and
implementations **MUST NOT** claim the stronger property.

### 5.1 Atomicity

Steps 1 to 7 are a read, a decision and a write. Performed as separate store
operations they are a time-of-check-to-time-of-use race, and the consequences
are not subtle: two verifications arriving together both read the live record,
both match it, and both return `ok`, so a single-use code is used twice. The
attempt counter loses increments to the same lost-update race, which makes the
budget of section 5 unenforceable by simply racing it.

Therefore:

1. Reading the record and removing it **MUST** be one atomic operation —
   Redis `GETDEL` or `EVAL`, `DELETE ... RETURNING`, or a row locked inside a
   transaction. The caller that obtains the record holds the only copy: it
   either consumes the code or writes it back with one more attempt spent.
2. Arming the cooldown **MUST** be an atomic reservation rather than a read
   followed by a write — `SET NX EX`, or an `add` that reports whether it
   stored. Otherwise two challenges arriving together both find no cooldown and
   both send.
3. Consuming a link token (sections 3.1, 3.2) **MUST** be atomic for the same
   reason: two `/start` messages carrying one token would otherwise both
   resolve it.
4. The webhook's idempotency marker (section 7.6) **MUST** be an atomic claim.

A store exposing only get, put and delete is **NOT** sufficient, and an
implementation **MUST NOT** present one as though it were. Using Redis does not
by itself make a get-check-delete sequence atomic.

Neither does writing the sequence inside one `async` function. In a
single-threaded runtime an `await` is a suspension point: the body stops there
and another caller runs, so `await read(); write()` interleaves exactly like two
separate operations. An atomic primitive implemented in-process **MUST**
complete its read, decision and write with nothing awaited in between.

Nor does a framework helper that *looks* like one operation. Laravel's
`Cache::pull()`, for example, is `get()` followed by `forget()` on every driver,
so building verification on it races exactly as a hand-written pair would. An
implementation **MUST** check what its framework's helper actually does, and
**MUST** either use a native primitive (`GETDEL`, `SET NX`, `DELETE ...
RETURNING`) or hold a per-key lock across the read and the write.

Where the atomicity comes from a lock, the guarantee is only as strong as the
lock driver, and an implementation **MUST** refuse a configuration that cannot
provide one rather than degrading quietly. A lock that is per-process or
per-server (an in-memory or file-backed driver) **MUST** be refused for
multi-process deployment: its data and its locks are both invisible to the next
worker.

When a lock is used, every *mutation* of a key **MUST** take it, not only the
read-modify-write one — an unlocked write can otherwise land inside another
caller's locked take, between its read and its delete, and be destroyed by it.

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
| Storage | A **keyed** hash of the code (HMAC-SHA-256 or stronger). The plaintext **MUST NOT** be written to the Store, to a log, to an audit trail or to an error response. |
| Hash key | **REQUIRED**, 32 bytes or more, held outside the Store it protects. |
| Hash binding | The authenticated input **MUST** include the `user_id`, so a digest is not interchangeable between accounts. |
| TTL | 2FA code 600 s or less. Default 300 s. |
| Cooldown | 60 s or more between sends for one `user_id`. Default 120 s. |

Codes are low-entropy, short-lived and single-use, so a fast hash is correct here;
a password-grade KDF would only add latency.

What does the work is the key, not the hash. A six-digit code has a million
possible values, so an **unkeyed** digest of one is reversed by a table anyone
can build in seconds — an implementation that hashes codes without a key, or
with an empty default key, protects nothing at all from whoever reads the Store,
while appearing to. That is why the key is required rather than recommended, and
why it **MUST NOT** live in the Store it protects.

Binding the digest to the `user_id` means a digest lifted from one account's
record cannot be matched against another's, and an attacker who dumps the Store
needs a fresh million-candidate search per account rather than one table for all
of them.

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
6. **Idempotency, as a claim rather than a marker.** `update_id` is unique per
   update and increases. An implementation **SHOULD** drop an `update_id` it has
   already processed; retries after a timeout are normal, and Telegram may
   deliver concurrently.

   The marker **MUST** be written as an atomic claim (section 5.1), not a read
   followed by a write, or two simultaneous deliveries both find nothing and
   both proceed.

   The claim **MUST NOT** be settled as processed before the work has succeeded.
   An implementation that marks an update done on arrival and then fails turns
   one transient error into a permanently lost operation: the retry arrives,
   sees the marker, and drops it. On failure the claim **MUST** be released, so
   that the retry is processed. Giving the claim a short lifetime and extending
   it on success achieves the same thing for a process that dies mid-handling.

   An implementation **MAY** still answer `200` for an update whose handling
   failed, and the reference implementations do: a non-2xx stalls the queue for
   every user of the bot, while a lost `/code` inconveniences one user who can
   ask again. That trade **SHOULD** be documented rather than silent, and does
   not apply to an operation the user cannot simply repeat.

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
| `<ns>:code:<user_id>` | `{ hash, expires_at, attempts, purpose, generation, challenge_id }` | code TTL |
| `<ns>:cooldown:<user_id>` | next-send unix timestamp, a bare integer | cooldown |
| `<ns>:link:<hash(token)>` | `{ user_id, expires_at }` (deeplink) or `{ chat_id, expires_at }` (paste), plus `replace` and `generation` for 3.3 | link TTL |
| `<ns>:update:<update_id>` | an opaque marker | retry window or longer |

`user_id` is an opaque string. Implementations **MUST NOT** assume it is an integer.

The cooldown value is a bare integer, and a Store **MAY** return a loosely typed
equivalent of what it was given — Laravel's Redis cache, for example, returns a
bare numeric as a numeric string, because it leaves such values unserialised so
that `INCR` still works on them. Implementations **MUST** therefore coerce when
reading it rather than comparing types strictly. This is the one field where it
matters, and it is invisible to any in-memory test.

**The field names above are normative, and they are `snake_case`.** They are the
wire format: two implementations sharing one Store must agree on them, and an
implementation that writes `expiresAt` where another reads `expires_at` has made
the Store unshareable while every one of its own tests passes. The same applies
to the shape — the cooldown is a bare integer, not an object wrapping one.

Implementations **SHOULD** verify this against the fixtures in `/conformance`
rather than against their own output, because an implementation that recomputes
its own expected values agrees with itself whatever it does.

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

- enforces the uniqueness rules of section 2 at the storage layer, and performs
  every enrollment change as a conditional transition on the generation
  (sections 2.1 and 2.2), with a generation that is not derived from the values
  it distinguishes and that survives the unlinked state;
- implements the deeplink flow of section 3.1, and the replacement flow of 3.3
  with the `replace` mark carried by the stored token, destination-safe, with
  authority pinned to the binding proved and codes in flight invalidated;
- writes and reads one key for both challenge directions (section 4);
- checks the purpose on every verification, with no way to skip it by omission,
  and treats `on_demand` as general-purpose (sections 4.2 and 5);
- performs verification, cooldown reservation, link-token consumption and the
  webhook claim atomically, with primitives it has verified to be atomic rather
  than ones that merely read as such, and refuses stores that cannot provide
  them (section 5.1);
- stamps each challenge with the enrollment generation and a challenge id,
  refuses a challenge from a superseded enrollment at acceptance, and drops a
  challenge on delivery failure only when it is still its own (sections 4.1 and
  5);
- keys its code hashes with a required secret, binds them to the `user_id`,
  compares in constant time, and enforces single use and an attempt budget
  (sections 5 and 6);
- rejects webhook requests without a valid secret token (section 7.1);
- never writes a code or a raw update body to a log (sections 6 and 7.4);
- releases its idempotency claim when handling fails (section 7.6);
- requires proof of a factor before unlinking (section 8);
- uses the key layout, field names and value shapes of section 9, checked
  against `/conformance`, and the error vocabulary of section 10;
- rejects configuration values that are not whole, finite numbers, since a
  comparison against NaN is false and a NaN therefore passes every bound.

The test suites in `packages/*/test` are written against these clauses and are the
executable form of this document.
