# Migration

Nothing here has been released, so there is no supported upgrade path between
pre-release states. This document exists because the changes below are breaking
in ways that are invisible until something goes wrong, and because anyone who
has already run an earlier revision of this branch needs to know what to do.

## Schema

Add the enrollment generation column. The published migration includes it; if
you ran an earlier version, add it separately:

```php
Schema::table('users', function (Blueprint $table) {
    $table->string('telegram_enrollment', 64)->nullable();
});
```

No backfill is required. A linked account with a null generation keeps working:
challenges issued against a null generation verify while it stays null, and the
first operation that needs a concrete generation — starting a chat replacement —
assigns one. The value is deliberately **not** cleared on unlink, so revocation
outlives the binding it revoked.

Also confirm the unique index on `telegram_chat_id` exists. Check for duplicates
before adding it:

```sql
SELECT telegram_chat_id, COUNT(*) c FROM users
WHERE telegram_chat_id IS NOT NULL
GROUP BY telegram_chat_id HAVING c > 1;
```

## Cache driver

**`array` and `file` are now refused at construction.** Neither is shared
between the processes that serve your requests: a code issued by one worker is
invisible to the next, and two workers can verify the same code. Use `redis` or
`memcached`:

```dotenv
TELEGRAM_2FA_CACHE_STORE=redis
```

For a test or a single-process script, `telegram-2fa.permit_local_cache_store`
re-enables them. Do not set it in production; the refusal is the feature.

## Required configuration

`TELEGRAM_2FA_HASH_PEPPER` is now **required**, at least 32 characters, and the
package refuses to start without it. A six-digit code has a million possible
values, so an unkeyed digest of one is reversed by a lookup table in seconds —
the empty default meant hashing the codes protected nothing while appearing to.

Setting it for the first time invalidates codes in flight, which is harmless:
users request another.

## Interface changes

If you implemented the contracts yourself rather than using the bundled
adapters:

**`CodeStore`** gained `take` and `add`. Both must be genuinely atomic — see
[SPEC.md 5.1](../SPEC.md#51-atomicity). Note that a framework helper that looks
like an atomic take often is not; Laravel's `Cache::pull()` is `get()` then
`forget()` on every driver.

**`IdentityStore`** replaced `link` and `unlink` with one conditional
`transition(userId, chatId|null, expected, next)`, and `Identity` gained a
nullable `chatId` and a `generation`. The compare-and-set is the point: a
validate-then-write pair leaves a window in which a recovery can land and be
silently overwritten.

**`Messages`** gained `unlinkInstructions`.

**`verify`'s** `purpose` is no longer optional-and-skippable; it defaults to
`login` and is always checked. Any call site confirming something privileged
must pass that action's own purpose, derived server-side.

## Record format

The stored challenge record gained `generation` and `challenge_id`, and field
names are `snake_case` in both languages — the Node package previously wrote
`camelCase`, which meant the two implementations could not read each other
despite the README claiming they could. Records written by an earlier revision
will not be read; they expire within minutes, so draining is unnecessary.

The committed fixtures in [`/conformance`](../conformance/records.json) are
`schema_version: 2`. Both test suites read them, so a field name drifting in one
implementation fails the other's suite.
