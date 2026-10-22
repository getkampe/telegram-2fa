# Porting to another language

[SPEC.md](../SPEC.md) is written to be implemented, not just read. This is the
checklist for doing that in Python, Go, Rust, Ruby, Elixir, C# or anything else,
plus the handful of places where a faithful-looking implementation goes wrong.

A port that satisfies the conformance list in SPEC.md section 11 interoperates
with the PHP and Node packages here: same bot, same store keys, same error
strings. Two implementations can even run against one database and one Redis
during a migration between stacks.

---

## The shape

Five pieces, in dependency order. The two reference packages are laid out this
way, so you can read either as you go.

### 1. Config, validated at construction

Reject what cannot be secure instead of warning about it. The bounds are in
SPEC.md sections 3, 5 and 6; the important ones:

- bot token matches `^\d+:[A-Za-z0-9_-]{30,}$`
- webhook secret matches `^[A-Za-z0-9_-]{32,256}$` — note Telegram itself allows
  one character, so the floor is yours to impose
- `code_ttl` 30 to 600, `cooldown` at least 30, `max_attempts` 1 to 10
- `link_code_length` at least 8

A configuration object that cannot be constructed in an insecure state removes a
whole class of deployment mistake, and costs ten lines.

### 2. Four interfaces

```
CodeStore       get(key) / put(key, value, ttl) / forget(key)
IdentityStore   find_by_user_id / find_by_chat_id / link / unlink
TelegramClient  send_message / answer_callback_query / get_me / set_webhook
Clock           now() -> unix seconds
```

Keep them this small. Everything else — framework integration, ORMs, HTTP
clients — lives in adapters outside the core, which is what makes the core
testable with maps and a fake.

The `Clock` looks like over-engineering until you test expiry and cooldown. Then
it is the difference between a suite that runs in milliseconds and one that
sleeps for five minutes.

### 3. Codes

CSPRNG only: `secrets` in Python, `crypto/rand` in Go, `SecureRandom` in Ruby.
Never the language's default `random` — it is seeded and predictable from prior
output, which for a 2FA code means an attacker who has seen a few can produce the
next.

Hash with HMAC-SHA256 and a pepper. Compare with a constant-time function:
`hmac.compare_digest`, `subtle.ConstantTimeCompare`, `Rack::Utils.secure_compare`.
Never `==`.

### 4. The protocol

`start_deep_link`, `complete_deep_link`, `start_paste_link`,
`complete_paste_link`, `start_chat_replacement`, `push`, `pull`, `verify`,
`unlink`, `unlink_after_external_proof`. Clause by clause from SPEC.md sections
3 to 8.

### 5. Webhook verification and an update handler

Verification is ten lines and is the most important ten lines in the port
(SPEC.md section 7). The handler dispatches `/start`, `/code`, `/status`,
`/link`, `/help`.

---

## The eight places a port goes wrong

These all produce an implementation that passes a manual test.

**1. Two keys for one code.** If `push` writes `code:<user_id>` and `verify`
reads anything else, the pull path still works, so the bot flow looks fine — and
every code your application pushes fails. One key, named in SPEC.md section 9.

**2. Re-storing the attempt counter with a fresh TTL.** The obvious way to
increment attempts is to write the record back with the standard TTL. That lets
an attacker keep one code alive forever by guessing wrong, and the time limit
stops existing. Re-store with `expires_at - now`.

**3. Returning the code.** A `ChallengeResult` carrying the code will end up in
an HTTP response, a log line or an exception payload. Generate it, hash it, send
it, drop it. Both reference packages assert on the serialised result, not just on
its fields, because that is where it leaks.

**4. Logging the update body.** `log.info("webhook", update)` leaks every code the
bot has ever delivered, in a form that is usually shipped off-host to a log
service. Log `update_id`, the update kind and the resolved user id.

**5. A short paste-flow code.** The paste flow's key is derived from the code, so
all outstanding codes share one namespace and six digits is enumerable. The
challenge code is scoped per user and may be six digits; the link code may not.
They are different values with different bounds — SPEC.md section 6.

**6. Chat uniqueness in application code only.** Two concurrent links of one chat
both pass the check. Put a unique constraint on the column and handle the
integrity error as `already_linked`.

**7. An optional purpose argument.** If `verify`'s purpose parameter is nullable
and a null means "compare against nothing", then the binding does nothing unless
every call site opts in — and the call site that forgets is both invisible and
the one that matters, a sign-in code approving a payout. Default it to `login`,
the same as `push`, and provide no wildcard. Remember that `on_demand` satisfies
everything (SPEC.md 4.2), or `/code` becomes useless for confirming an unlink.

**8. Taking the replace mark from the caller.** In the replacement flow (3.3) the
`replace` flag must be read from the stored token, not from an argument to the
resolving call. A port that accepts `complete_deep_link(token, chat_id, replace:
true)` has made the proof step optional, which is the entire point of the flow.

---

## Testing a port

Work from the test names in `packages/php/tests` or `packages/node/test` — they
are a conformance suite in all but name, and each maps to a numbered clause.
The ones that catch real bugs:

- a pushed code and a pulled code both verify through the same call
- a verified code does not verify a second time
- a wrong guess does not extend the code's life
- the attempt budget destroys the code
- a login code does not satisfy a withdrawal, and omitting the purpose means
  login rather than a wildcard
- an on-demand code satisfies any purpose
- an ordinary link token cannot move an already-verified binding
- a numerically-equal-but-textually-different code fails (catches `==` on digit
  strings in loosely typed languages)
- a prefix and an extension of the webhook secret are both rejected
- a repeated `update_id` is dropped
- one chat cannot become the factor for a second account
- a group chat gets no code

You will not need a Telegram connection for any of them. A fake client that
records outgoing messages is enough, and the code can be read back out of the
message the fake captured — which is also a neat demonstration that the library
is not returning it anywhere else.

---

## Contributing a port back

A port in a new language is welcome in `packages/<language>/`. What is expected:

- the conformance list in SPEC.md section 11, demonstrably
- the test cases above, in the language's idiomatic framework
- a `README.md` with install, minimal wiring, and a framework adapter if the
  language has an obvious one
- CI wired into `.github/workflows/ci.yml`
- no dependencies beyond the standard library, if the language's standard library
  can do HTTP and HMAC

If the specification is ambiguous or wrong somewhere, open an issue about the
specification first. It is the thing the implementations agree on, so it is the
thing worth fixing.
