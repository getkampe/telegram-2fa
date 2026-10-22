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

## Linking — replacing a chat

The user has a new Telegram account. Linking never silently moves a verified
binding — a flow that did would let anyone holding a session attach their own
chat — so replacement is explicit and costs a code from the chat being replaced.

```
App                                        User / old chat        New chat
 │                                               │                   │
 ├─ push(userId, 'replace') ───────────────────►  │                   │
 │                                               │                   │
 ├─ startChatReplacement(userId, code)            │                   │
 │    verify under purpose 'replace'              │                   │
 │    mint token {userId, replace: true}          │                   │
 │                                                │                   │
 ├─ t.me/bot?start=<token> ─────────────────────────────────────────► │
 │                                                │   /start <token>  │
 │◄───────────────────────────────────────────────────── webhook ──── ┤
 │    completeDeepLink → bind(replace: true)                          │
 │      notify old chat, unlink old, bind new                         │
```

Two properties worth preserving if you reimplement this:

- **The `replace` mark lives on the stored token**, not on the call that resolves
  it. Taking it from the resolution side makes the proof step skippable by
  presenting an ordinary token.
- **The old chat stays linked until the new one is resolved**, and is only
  released by the same write that takes the new binding. Authorising a
  replacement the user never finishes must not leave the account factorless, and
  neither must one that is refused because the destination is taken.
- **The token is pinned to the binding it proved.** Once that binding changes —
  through recovery, unlinking, or another replacement — the token is void, so
  authority cannot outlive the factor it was granted over.
- **Codes in flight are dropped when the binding moves**, since a code delivered
  to the old chat is proof held by whoever still has that chat.

A user who has lost the old chat entirely cannot complete step one, and belongs
in the recovery path below.

---

## Challenge — push

Your application needs proof, now: a login, a withdrawal, an email change.

```
push(userId, purpose)
  │
  ├─ identities.findByUserId(userId)
  │    └─ absent or linkedAt null  →  not_linked
  │
  ├─ ADD cooldown:<userId>         ← atomic reservation; losing it means
  │    └─ already held             →  cooldown, with next_send_at
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
verify(userId, code, purpose = 'login')
  │
  ├─ TAKE code:<userId>                 ← atomic get-and-delete, not get
  │    └─ absent                        →  expired
  ├─ attempts >= 5                      →  too_many_attempts, forget key
  ├─ now > expires_at                   →  expired, forget key
  ├─ purpose not satisfied              →  spend an attempt, report invalid
  ├─ hash_equals(stored, h(code))?
  │    ├─ no   →  attempts++, re-store with (expires_at - now) TTL
  │    │           └─ budget spent  →  too_many_attempts, forget key
  │    │           └─ otherwise     →  invalid, with attempts_remaining
  │    └─ yes  →  forget key, ok
```

Four properties to preserve in any reimplementation: the **atomic take**, single
use on success, the attempt budget destroying the code, and the re-store **not**
extending the code's lifetime.

The take is the one that is easy to get wrong and hard to notice. Reading the
record, deciding, and deleting it afterwards leaves a window in which a second
request reads the same live record — so one code verifies twice, and the attempt
counter loses increments to the same lost update. Taking the record means the
winner holds the only copy and a concurrent caller finds nothing. See
[SPEC.md 5.1](../SPEC.md#51-atomicity).

### Purpose

`purpose` names the step a code authorises. It defaults to `login` on both
`push` and `verify`, and **cannot be skipped** — there is no "match anything"
value, because a default of "compare against nothing" means the binding does
nothing unless every call site opts in, and the call site that forgets is both
invisible and the one that matters.

| Code issued by | Stored purpose | Satisfies |
| --- | --- | --- |
| `push(userId)` | `login` | `login` only |
| `push(userId, 'withdrawal')` | `withdrawal` | `withdrawal` only |
| `pull(chatId)` — the user sent `/code` | `on_demand` | **any** purpose |
| `push(userId, 'replace')` | `replace` | `replace` only |
| `push(userId, 'unlink')` | `unlink` | `unlink` only |

`on_demand` is the one general-purpose code, and it is sound because the user
asked for it deliberately: nothing the application did caused it to exist. It is
also what keeps `/code` useful for confirming an unlink or a replacement.

A purpose mismatch returns `invalid` and spends an attempt. It does not get its
own error code — telling a caller that a live code exists for a different step is
information it has not proved it should have — and it is budgeted so the mismatch
path is not a free oracle.

---

## Unlinking

```
unlink(userId, code)
  ├─ not linked                        →  not_linked
  ├─ verify(userId, code, 'unlink')    →  propagate any failure
  ├─ identities.unlink(userId)
  ├─ forget code: and cooldown:
  └─ notify the chat
```

Verification is under purpose `unlink`, so a code pushed to confirm a sign-in
cannot remove the factor. A code the user fetched with `/code` still works,
because `on_demand` is general-purpose — which is what the bot's `/unlink`
instructions tell them to do.

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
| `link:<h(token)>` | `startDeepLink`, `startPasteLink`, `startChatReplacement` | the matching complete | first resolution, or TTL |
| `code:<userId>` | `push`, `pull` | `verify` (takes it) | any verification, budget spent, expiry, unlink, replacement |
| `cooldown:<userId>` | `push`, `pull` (reserve) | the reservation itself | TTL, delivery failure, unlink, replacement |
| `update:<updateId>` | the update handler | the update handler | TTL |
| chat id + linkedAt | `link` | everything | `unlink` |

Everything except the last row is short-lived cache. Losing the cache logs
nobody out; it only invalidates codes in flight, and the user requests another.
