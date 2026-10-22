# Security

Two things live in this file: how to report a vulnerability, and the threat model
the design answers to. The second half is the more useful one if you are porting
the protocol or reviewing an implementation, because it says *why* each rule in
[SPEC.md](SPEC.md) is there.

---

## Reporting a vulnerability

Open a [private security advisory](https://github.com/getkampe/telegram-2fa/security/advisories/new)
on this repository, or e-mail **support@getkampe.com** if that form is not
available to you. Please do not open a public issue for anything exploitable.

Include the version or commit, which package, and the smallest reproduction you
can manage. A first response should arrive within a few days.

The e-mail address is listed as well as the form on purpose: private
vulnerability reporting is a setting a repository can have switched off, and a
reporter who meets a page they cannot use will often give up rather than hunt
for another route — which is the worst outcome for everyone.

---

## What Telegram gives you, and what it does not

**It gives you** transport security to Telegram's servers, delivery to a device
the user has already authenticated, no per-message cost, no SIM-swap surface, and
no carrier in the path.

**It does not give you end-to-end encryption.** A bot chat is a *cloud chat*:
encrypted client-to-server and between Telegram's own data centres, but readable
by Telegram, and backed up to their infrastructure. End-to-end encryption in
Telegram exists only in Secret Chats, which bots cannot use. So the codes this
library sends are visible to Telegram and to anyone who compromises the user's
Telegram account — which is a weaker guarantee than an authenticator app, where
the secret never leaves the device. If your threat model includes the messaging
provider, this is not the factor for you.

**It does not give you** control of the recipient's Telegram account. If someone
has the user's Telegram session, they have the codes. Telegram as a second factor
is therefore a *possession* factor bound to a Telegram account — about as strong
as the user's Telegram security, which can be weaker than the account you are
protecting if they have no cloud password set.

Two consequences shape this library:

1. A chat that can read codes is not allowed to *remove* the factor
   (SPEC.md section 8). Otherwise a stolen phone silently downgrades the account
   to one factor for good.
2. The bot never reveals more about the account than it has to. The link
   confirmation takes a caller-supplied label precisely so you can mask it: that
   message sits in a chat history that may be read over someone's shoulder.

---

## Threat model

### T1 — A forged webhook request

**The attack.** The webhook URL is public and takes an unauthenticated POST. Its
payload asserts "chat id X sent /code". An attacker who learns or guesses the URL
posts such an update for a chat id that is not theirs. The bot mints a code for
the linked account.

**Why it is bad and quiet.** The code is delivered to the *real* owner's chat, so
the attacker does not read it — but they now control the timing of code issuance,
can burn the victim's cooldown, can spam them into ignoring the bot, and on an
implementation where the code is echoed anywhere in the response, can read it
outright. Nothing in the application logs looks wrong.

**The mitigation.** `secret_token` on `setWebhook`, and a constant-time check of
`X-Telegram-Bot-Api-Secret-Token` on every request. Mandatory here: `Config`
refuses to construct without a 32-character-minimum secret, and the Laravel route
ships with the middleware attached. Optionally also restrict to Telegram's
published ranges — but only when the peer address is real, which behind a proxy
it is not.

### T2 — Guessing a code

**The attack.** Six digits is 10^6. With unlimited attempts and a five-minute
window, a script needs about 3 300 requests per second to be sure within one
window — or, far more realistically, it grinds a few attempts per challenge
across thousands of challenges and waits.

**The mitigation.** Five attempts per code, after which the code is destroyed and
the user must request another. This turns the search into 1 chance in 200 000 per
challenge, and every spent challenge is visible to the user as a message they did
not ask for. Rate limiting the HTTP endpoint is necessary too, and is the host
application's job.

A subtler version: an implementation that increments the attempt counter by
re-storing the record with a *fresh* TTL lets an attacker keep one code alive
indefinitely by guessing wrong. The time limit then does not exist. Both packages
re-store under the code's own remaining lifetime, and a test asserts it.

### T3 — Reading codes out of storage or logs

**The attack.** A dumped Redis instance, a leaked log aggregator, a stack trace
in an error tracker, an audit table someone copies to a spreadsheet.

**The mitigation.** Codes are stored as HMAC-SHA256 digests, never plaintext.
Nothing in either package writes a code, a link token or a raw Telegram update
body to a log — and the update body is the important one, because for this bot
the update body *is* the code. Logging the whole payload at `info` is the single
most common way a Telegram 2FA implementation leaks every code it has ever sent.

**The key is the part that matters, not the hash.** A six-digit code has a
million possible values, so an *unkeyed* digest of one is reversed by a table
anyone can build in seconds — hashing without a key protects nothing from
whoever reads the store, while looking as though it does. `TELEGRAM_2FA_HASH_PEPPER`
is therefore required: both packages refuse to start without at least 32
characters of it, and it belongs outside the store it protects.

Digests are also bound to the `user_id`, so one lifted from a dump cannot be
matched against another account's record, and an attacker needs a fresh
million-candidate search per account rather than one table for all of them.

### T4 — Replaying a code

**The attack.** A code that survives verification can be used again — from a
request log, a browser history entry, a proxy cache, or the chat itself.

**The mitigation.** Single use. The record is deleted the moment it verifies.

A code is also bound to a `purpose`, so one minted to confirm a login cannot be
presented as proof for a withdrawal. Two details make that binding real rather
than decorative:

- **It cannot be skipped by omission.** `verify` defaults its purpose to `login`,
  the same as `push`, and there is no wildcard. An implementation where omitting
  the argument means "compare against nothing" provides no binding at all unless
  every call site opts in, and the call site that forgets is both invisible and
  the one that matters.
- **Derive the purpose from the action, server-side.** If the client sends it
  along with the code, a client can simply ask for whichever purpose its code
  happens to carry, and the binding is back to decoration.

A mismatch returns `invalid` and spends an attempt — it gets no distinct error,
because telling a caller that a live code exists for a different step is
information it has not proved it should have, and it is budgeted so the mismatch
path is not a free oracle.

The one exception is `on_demand`, the purpose of a code the user fetched with
`/code`. It satisfies any purpose, because such a code cannot know what it is
for and the user asked for it deliberately — nothing the application did caused
it to exist.

### T5 — A link token redirected to the wrong chat or account

**The attack, deeplink flow.** The token travels through a chat message, so it is
visible to anyone with access to that chat. If it survives its first use, whoever
saw it can present it from their own chat.

**The mitigation.** Single use, burned *before* the link is attempted; 192 bits of
entropy; hashed at rest; a 10-minute lifetime.

**The attack, paste flow.** The store key is derived from the code itself, so
every outstanding code in the system shares one namespace. A six-digit code there
is enumerable: an attacker pastes random codes into their own settings page until
one resolves, and whoever generated it has their Telegram bound to the attacker's
account — a factor the attacker controls, attached to an account they are
presumably also attacking.

**The mitigation.** Eight Crockford-base32 characters (40 bits), authenticated
session required, endpoint rate-limited. This is also why the deeplink flow is
the recommended one: the token is bound to an account before it is ever shown.

### T6 — One Telegram account as the factor for many accounts

**The attack.** An attacker links their own chat to a victim's account — or links
one chat to many accounts — so that one Telegram account unlocks all of them.

**The mitigation.** A unique index on the chat id column, plus an application
check that refuses to move an existing link. The index is the part that matters:
two concurrent link attempts both pass the application check, and only one can
pass the index. The packages catch the resulting integrity error and return
`already_linked`.

Because no ordinary link flow may move a verified binding, a user with a new
Telegram account goes through `startChatReplacement`, which costs a code from the
chat being replaced. The flag authorising the rebinding is stored with the link
token rather than passed to the call that resolves it — taken from the caller, it
would make that proof step skippable by presenting an ordinary token.

### T7 — Removing the factor with a stolen session

**The attack.** An attacker with a session cookie but no phone goes to settings
and unlinks Telegram, leaving a single-factor account.

**The mitigation.** `unlink` requires a current code, verified under purpose
`unlink`, so a code pushed to confirm a sign-in cannot remove the factor. A code
the user fetched with `/code` works, which is what the bot's `/unlink`
instructions tell them to do.

For genuine recovery — the user lost the Telegram account —
`unlinkAfterExternalProof` exists, and takes a reason for the audit trail; the
caller is responsible for the proof, and should require another enrolled factor
or an out-of-band identity check.

The bot's own `/unlink` command explains where to do it and does not do it.
Whoever holds the phone can already read the codes; letting them also remove the
factor, with no session and no password, turns a stolen phone into a permanently
single-factor account.

### T8 — Racing the single-use rule

**The attack.** Submit the same code twice at the same moment. A verification
built from read-check-delete has a gap between the check and the delete, and
both requests pass through it: both read the live record, both match, both
return success. One code, two authorised actions — two withdrawals from one
approval, if the application treats verification as the gate.

The same gap makes the attempt budget unenforceable. Incrementing a counter by
reading it and writing it back loses updates under concurrency, so an attacker
who fires guesses in parallel gets far more than five.

**The mitigation.** The store contract requires two atomic primitives, and the
library is built on them: `take` (atomic get-and-delete) and `add` (atomic
set-if-absent). Verification *takes* the record, so exactly one caller holds it
— that caller either consumes the code or writes it back with one more attempt
spent, and a concurrent caller finds nothing. Cooldowns, link-token consumption
and the webhook's idempotency marker use the same primitives.

Choosing Redis does not by itself fix this; a get-check-delete sequence against
Redis races exactly as happily. Neither does a framework helper that reads like
one operation — Laravel's `Cache::pull()` is `get()` then `forget()` on *every*
driver, and an earlier revision of this package was built on it and said in a
comment that Redis made it atomic. It never did.

The Laravel adapter therefore serialises every mutation of a key behind that
store's own named lock, and refuses a store that cannot provide one. `array` and
`file` are refused outright: their data and their locks are per-process and
per-server respectively, so the next worker sees neither. The Node Redis store
resolves `GETDEL`/`EVAL` at construction and throws if the client has neither.

An `async` method is not automatically atomic either, and this is where the Node
package was wrong for a while: `MemoryCodeStore.take()` read the value with
`await this.get(key)` and then deleted it. The `await` is a suspension point, so
two concurrent verifications both received the record and both succeeded — under
a comment asserting there was no gap. The in-memory primitives now read, decide
and write with nothing awaited in between, and `Promise.all` of two real calls
is a test in the suite rather than a thought experiment.

**Honest limit:** where the atomicity comes from a lock, the guarantee is
exactly as strong as the lock driver. Redis and Memcached locks are
cross-process; nothing in this package can verify that your Redis is not, say, a
cluster of independent nodes behind one address. The cross-process behaviour is
covered by an integration suite that runs against a live Redis in CI and skips
itself elsewhere — and CI fails if it skips, because a guarantee resting on a
skipped test is not a guarantee.

### T9 — Authority that outlives the factor it was granted over

**The attack.** Start a chat replacement, proving possession of the current
Telegram account, and keep the resulting link token. Then wait: the user loses
their Telegram account and recovers through support, linking a fresh chat. Now
present the old token. If it only records "this user may replace their chat", it
is honoured, and the attacker's chat becomes the second factor for an account
they never had access to.

**The mitigation.** A replacement token records the *enrollment generation* it
proved — a random 128-bit value, changed by every transition and kept when the
account is unlinked — and that value is the expectation of the conditional write
that rebinds the chat.

Three details, all learned the hard way. The generation must not be derived from
the state it distinguishes: a digest of the chat id and its verification
timestamp repeats when the same chat is unlinked and relinked inside one second,
which revives every token minted beforehand. Checking it before writing is not
enough, because a recovery can land in between; the check has to *be* the write,
as a compare-and-set.

And the generation a token records must be the one that was **proved**, captured
before the code is verified. An earlier version re-read the enrollment
afterwards — intending to fail early if anything had changed — and so recorded
whatever it found, which in the case that matters is the *recovered*
enrollment's generation. That turned a defensive read into the vulnerability it
was meant to prevent: the token acquired authority over an enrollment the user
had never proved, and replaced the chat the user had just recovered onto. A
change during verification is now refused outright.

The related failure is quieter: a replacement that is refused must not cost the
user the factor they already had. Releasing the old binding before checking the
destination meant a request that failed still stripped the account of its second
factor. The move is now a single write that either takes the new binding or
leaves the old one untouched, and the old chat is not told it has been unlinked
until the move has succeeded.

Codes already in flight are dropped when a binding moves, since a code delivered
to the old chat is proof in the hands of whoever still holds that chat. More
importantly, each challenge carries the generation it was issued against and is
refused at acceptance if that generation is no longer current — so a challenge
that survives the cleanup, by racing it, is inert rather than dangerous.

**Honest limit:** preventing a stale challenge from being written back is
best-effort, because a verification that has already taken the record can be
racing the revocation. What is guaranteed is that such a record cannot be
accepted. The packages do not claim the stronger property, and a test asserts
the weaker one by resurrecting a record by hand.

### T10 — The bot as an amplifier

**The attack.** Your bot token can message anyone who has started the bot. An
unthrottled challenge endpoint makes your application a way to send someone
unlimited Telegram messages.

**The mitigation.** A per-account cooldown of at least 30 seconds, default 120,
enforced in the library rather than left to the caller. Update deduplication also
closes the retry path: without it, Telegram's own retries mint extra codes.

### T11 — Codes handed to the bot by a confused user

**The attack.** A user pastes a code into the bot chat instead of the website. On
an implementation that parses free text as a code, the bot has now received the
code — and if the update body is logged, it is in the logs twice.

**The mitigation.** Codes travel application-to-user only. Free text in the chat
gets a nudge, never a parse. The handler ignores non-private chats entirely, so a
bot added to a group never issues a code in front of its members.

---

## What is enforced, and what is not

Enforced by the adapters, with a test that fails if the protection is removed:

- exactly one success among concurrent correct verifications — asserted through
  `Promise.all` against the shipped store, not only through a test wrapper that
  opens the window by hand
- every evaluated guess counted, so the attempt budget cannot be beaten by
  parallelism. Note what this does *not* mean: firing ten guesses at once spends
  one attempt, not ten, because only the caller holding the record has its guess
  compared at all. A guess that is never evaluated cannot be a hit.
- the generation a replacement token carries is the one that was proved, and
  authorisation is refused if the enrollment moved during verification
- every enrollment change conditional on the generation, a conflict leaving the
  current binding untouched
- revocation surviving unlink and relink, including inside one second
- a challenge from a superseded enrollment never accepted
- a delivery failure dropping only its own challenge
- a refused replacement leaving the original binding in place

Not claimed:

- **No cross-store transaction.** The identity store and the code store are
  different systems. What makes the gap between them safe is the generation
  check at acceptance, not a distributed transaction.
- **Lock-driver dependence**, as described in T8. Covered against a live Redis —
  cross-instance lock visibility, server-enforced expiry, and the whole protocol
  end to end over the wire — in CI and locally against Redis 5 and 7. **Not**
  covered against Memcached, DynamoDB or the database driver.
- **The SQL compare-and-set** is covered against SQLite in memory — real
  constraints, real affected-row counts — but **not** against MySQL or
  PostgreSQL. The unique-violation mapping checks both SQLSTATE classes those
  use; that mapping is unverified on the real engines.
- **No protection against a compromised Telegram account**, which is inherent to
  the factor rather than a defect — see the top of this document.

## Deployment checklist

Upgrading an existing install first: [docs/migration.md](docs/migration.md) —
there is a new column, two newly refused cache drivers and a now-required
secret.

- [ ] `TELEGRAM_WEBHOOK_SECRET` set, 32+ characters, and the webhook registered
      with it (`php artisan telegram:webhook`, or `setWebhook` directly).
- [ ] `TELEGRAM_2FA_HASH_PEPPER` set to a long random string, held somewhere
      other than the store it protects. Both packages refuse to start without it.
- [ ] The cache store gives the library real atomic primitives. Laravel: `redis`
      or `memcached`, not `database`, `file` or `array`. Node: a Redis client
      with `GETDEL` or `EVAL`. See T8 — this is a correctness requirement, not a
      performance preference.
- [ ] The bot token is in the environment, not in a committed config file. Rotate
      it through @BotFather if it has ever been committed.
- [ ] The cache store is shared across processes and survives a deploy — Redis,
      Memcached or a database table. Not `array`, not `file`.
- [ ] The unique index on the chat id column exists. Check the migration ran.
- [ ] The challenge and verify endpoints are rate-limited per account and per IP.
- [ ] Every privileged action passes its own `purpose` to both `push` and
      `verify`, and derives it server-side rather than from the request body.
- [ ] The webhook route is excluded from CSRF — and nothing else is.
- [ ] HTTPS everywhere. Telegram refuses to deliver to anything else; make sure
      your own redirect does not strip the secret header.
- [ ] Your logs do not contain codes. Grep for one after a test run.
- [ ] Unlinking requires proof, in whatever UI you built around it.
