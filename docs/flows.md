# The flows, end to end

What actually happens, in order, with the state each step reads and writes. Useful
when you are building the UI around the library, or debugging why a code will not
verify.

Keys below are shown without the configurable `tg2fa:` prefix.

---

## Linking — deeplink (recommended)

The user is signed in, on a settings page, and taps a button.

```
┌────────────┐                ┌──────────┐              ┌─────────────┐
│    App     │                │   User   │              │ Bot/Webhook │
└─────┬──────┘                └────┬─────┘              └──────┬──────┘
      │                            │                           │
  startDeepLink(userId)            │                           │
      │  nonce = 192 bits          │                           │
      │  put link:h(nonce)         │                           │
      │      = {userId}, 600s      │                           │
      │                            │                           │
      ├─ t.me/bot?start=nonce ────►│                           │
      │     (button, or QR)        │                           │
      │                            ├─── taps ─────────────────►│
      │                            │                           │
      │                            │          /start <nonce>   │
      │◄──────────────────────── webhook ────────────────────── ┤
      │  completeDeepLink(nonce, chatId)                        │
      │    get link:h(nonce) → {userId}                         │
      │    forget link:h(nonce)        ← single use, burned     │
      │    reject if user or chat already linked                │
      │    identities.link(userId, chatId)                      │
      │                                                         │
      ├── "this chat is now your second factor" ───────────────►│
```

**UI notes.** Show the QR code as well as the button: desktop users have Telegram
on their phone. Poll or use a websocket to notice the link completing, because
the confirmation arrives out of band — the user's browser learns nothing from the
tap. A 10-second poll against `isLinked()` is enough.

**Minting is cheap and unauthenticated-safe.** You can call `startDeepLink` on
page load. The account check happens at completion.

---

## Linking — paste

For when tapping a link is not possible: a locked-down desktop, a user who found
the bot first, a support agent walking someone through it.

```
User                      Bot/Webhook                           App
 │                            │                                  │
 ├── /link ──────────────────►│                                  │
 │                       startPasteLink(chatId)                   │
 │                         code = 8 × base32                      │
 │                         put link:h(code)                       │
 │                             = {chatId}, 600s                   │
 │◄── shows "K3M9QW7P" ───────┤                                  │
 │                                                                │
 ├── types it into the signed-in settings page ──────────────────►│
 │                                      completePasteLink(userId, code)
 │                                        get link:h(code) → {chatId}
 │                                        forget link:h(code)
 │                                        identities.link(userId, chatId)
```

**The endpoint must be authenticated and rate-limited.** `userId` comes from the
session, never the request body. The code's store key is derived from the code
itself, so all outstanding codes share one namespace — which is why the code is
8 base32 characters rather than 6 digits, and why the rate limit is not optional.
See [SECURITY.md T5](../SECURITY.md#t5--a-link-token-redirected-to-the-wrong-chat-or-account).

---

## Challenge — push

Your application needs proof, now: a login, a withdrawal, an email change.

```
push(userId, purpose)
  │
  ├─ identities.findByUserId(userId)
  │    └─ absent or linkedAt null  →  not_linked
  │
  ├─ get cooldown:<userId>
  │    └─ in the future            →  cooldown, with next_send_at
  │
  ├─ code = 6 digits (CSPRNG)
  ├─ put code:<userId> = {hash, expires_at, attempts: 0, purpose}, 300s
  ├─ put cooldown:<userId> = now + 120, 120s
  │
  ├─ telegram.sendMessage(chatId, code)
  │    └─ failed  →  forget both keys, send_failed
  │
  └─ ok, with expires_at and next_send_at
```

The delivery failure path matters: a code the user never received must not occupy
the slot, or the account is stuck behind a cooldown for a code nobody has.

**The code is not in the result.** Generated, hashed, sent, dropped — so the
result object is safe to serialise straight into an HTTP response.

---

## Challenge — pull

The user would rather fetch a code than wait for one, or your sending path is
down.

```
/code  →  pull(chatId)
            ├─ identities.findByChatId(chatId)   →  not_linked
            ├─ same cooldown check
            ├─ same key: code:<userId>           ← the single-key rule
            └─ bot replies with the code
```

Both directions write `code:<userId>`, so one `verify()` call accepts either.
An implementation that writes one key and reads another appears to work, because
the pull path is the one people test by hand, while every pushed code silently
fails ([SPEC.md section 4](../SPEC.md#4-challenge)).

---

## Verification

```
verify(userId, code, purpose?)
  │
  ├─ get code:<userId>
  │    └─ absent                        →  expired
  ├─ attempts >= 5                      →  too_many_attempts, forget key
  ├─ now > expires_at                   →  expired, forget key
  ├─ purpose given and does not match   →  spend an attempt
  ├─ hash_equals(stored, h(code))?
  │    ├─ no   →  attempts++, re-store with (expires_at - now) TTL
  │    │           └─ budget spent  →  too_many_attempts, forget key
  │    │           └─ otherwise     →  invalid, with attempts_remaining
  │    └─ yes  →  forget key, ok
```

Three properties to preserve in any reimplementation: single use on success, the
attempt budget destroying the code, and the re-store **not** extending the code's
lifetime.

---

## Unlinking

```
unlink(userId, code)
  ├─ not linked                 →  not_linked
  ├─ verify(userId, code)       →  propagate any failure
  ├─ identities.unlink(userId)
  ├─ forget code: and cooldown:
  └─ notify the chat
```

Proof of the factor is required to remove it. For a user who lost the Telegram
account, `unlinkAfterExternalProof(userId, reason)` skips the check and records
the reason — the caller owns the proof, and should require another enrolled
factor or an out-of-band identity check.

The chat is notified either way. If someone else removed the factor, that message
is how the user finds out.

---

## State summary

| Key | Written by | Read by | Cleared by |
| --- | --- | --- | --- |
| `link:<h(token)>` | `startDeepLink`, `startPasteLink` | the matching complete | first resolution, or TTL |
| `code:<userId>` | `push`, `pull` | `verify` | success, budget spent, expiry, unlink |
| `cooldown:<userId>` | `push`, `pull` | `push`, `pull` | TTL, delivery failure, unlink |
| `update:<updateId>` | the update handler | the update handler | TTL |
| chat id + linkedAt | `link` | everything | `unlink` |

Everything except the last row is short-lived cache. Losing the cache logs
nobody out; it only invalidates codes in flight, and the user requests another.
