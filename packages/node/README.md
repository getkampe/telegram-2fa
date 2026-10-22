# @kampe/telegram-2fa

Telegram as a second authentication factor for Node 18+. TypeScript, zero runtime
dependencies, no framework assumptions.

Implements [SPEC.md](../../SPEC.md) v1.0. The
[PHP package](../php) in the same repository implements the same protocol, so
both can run against one bot and one database.

```bash
npm install @kampe/telegram-2fa
```

---

## Wiring

```ts
import {
  Config,
  DefaultMessages,
  FetchTelegramClient,
  RedisCodeStore,
  TelegramTwoFactor,
} from '@kampe/telegram-2fa'

const config = Config.fromEnv()        // or new Config({ ... })

const tfa = new TelegramTwoFactor({
  config,
  store: new RedisCodeStore(redis),    // or MemoryCodeStore for tests
  identities: myIdentityStore,         // 4 methods — the only adapter you write
  telegram: new FetchTelegramClient({ botToken: config.botToken }),
  messages: new DefaultMessages(),
})
```

`Config` validates on construction and throws `ConfigurationError` rather than
accepting something that cannot be secure — a missing webhook secret, an
unlimited attempt budget, a code lifetime measured in days.

`Config.fromEnv()` reads `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`,
`TELEGRAM_WEBHOOK_SECRET`, `TELEGRAM_2FA_HASH_PEPPER` and the optional
`TELEGRAM_2FA_CODE_TTL`, `_COOLDOWN`, `_MAX_ATTEMPTS`, `_APP_NAME`.

`TELEGRAM_2FA_HASH_PEPPER` is required and must be at least 32 characters: it is
the HMAC key for code hashes, and a six-digit code has only a million possible
values, so an unkeyed digest of one is reversed by a table anyone can build in
seconds.

### The identity store

Three methods over your own users table. In Prisma:

```ts
import { ANY_GENERATION, ChatAlreadyLinked, type Identity, type IdentityStore } from '@kampe/telegram-2fa'

const toIdentity = (u: {
  id: string
  telegramChatId: string | null
  telegramLinkedAt: Date | null
  telegramEnrollment: string | null
}): Identity => ({
  userId: u.id,
  chatId: u.telegramChatId,
  linkedAt: u.telegramLinkedAt === null ? null : Math.floor(u.telegramLinkedAt.getTime() / 1000),
  generation: u.telegramEnrollment,
})

const identities: IdentityStore = {
  async findByUserId(userId) {
    const user = await prisma.user.findUnique({ where: { id: userId } })

    // Returned even when no chat is linked: the generation outlives the
    // binding, so a token minted before an unlink stays void after a relink.
    return user === null ? null : toIdentity(user)
  },

  async findByChatId(chatId) {
    const user = await prisma.user.findUnique({ where: { telegramChatId: chatId } })

    return user === null ? null : toIdentity(user)
  },

  async transition(userId, chatId, expected, next) {
    // The comparison is part of the write. Validating in application code and
    // then writing leaves a window in which a recovery can land and be
    // silently overwritten — which is how a replacement token outlives the
    // enrollment it proved.
    try {
      const { count } = await prisma.user.updateMany({
        where: {
          id: userId,
          ...(expected === ANY_GENERATION ? {} : { telegramEnrollment: expected }),
        },
        data: {
          telegramChatId: chatId,
          telegramLinkedAt: chatId === null ? null : new Date(),
          telegramEnrollment: next,
        },
      })

      if (count !== 1) {
        return null // changed under us; nothing was written
      }
    } catch (error) {
      // P2002 is Prisma's unique-constraint violation. The @unique on
      // telegramChatId is what actually guarantees one chat per account: two
      // concurrent transitions both pass an application check, and only one can
      // pass the index.
      if ((error as { code?: string }).code === 'P2002') {
        throw new ChatAlreadyLinked('That chat is already a second factor.')
      }

      throw error
    }

    return identities.findByUserId(userId)
  },
}
```

The matching schema:

```prisma
model User {
  id                 String    @id @default(cuid())
  telegramChatId     String?   @unique      // the @unique is load-bearing
  telegramLinkedAt   DateTime?
  telegramEnrollment String?                // kept when unlinked, on purpose
}
```

### The webhook

```ts
import { SECRET_HEADER, UpdateHandler, WebhookVerifier } from '@kampe/telegram-2fa'

const verifier = new WebhookVerifier(config)
const handler = new UpdateHandler({ tfa, config, store, telegram, messages })

app.post('/telegram/webhook', express.json({ limit: '64kb' }), async (req, res) => {
  if (!verifier.accepts(req.get(SECRET_HEADER), req.ip)) {
    return res.sendStatus(403)
  }

  try {
    await handler.handle(req.body)
  } catch (error) {
    // The failure, never the payload: the payload contains the codes.
    console.error('telegram-2fa: handler failed', { updateId: req.body?.update_id })
  }

  res.json({ ok: true })    // always 200 — see SPEC.md 7.5
})
```

Skipping the verifier makes the endpoint accept "this chat id is asking for a
code" from anyone who finds the URL. See
[SECURITY.md T1](../../SECURITY.md#t1--a-forged-webhook-request).

Adding your own commands:

```ts
handler.on('balance', async (chatId, argument) => {
  await telegram.sendMessage(chatId, `Balance: ${await balanceFor(chatId)}`)
})
```

---

## API

Every method is async.

### Linking

| Method | Purpose |
| --- | --- |
| `startDeepLink(userId)` | Mint a nonce bound to the account; `.url` is the `t.me` link. |
| `completeDeepLink(token, chatId)` | Resolve a `/start` payload. Single use. |
| `startPasteLink(chatId)` | Bot side: mint an 8-character code bound to the chat. |
| `completePasteLink(userId, code)` | Authenticated page side. Rate-limit this. |
| `startChatReplacement(userId, code)` | Move to a new Telegram account, proving the old one first. Narrow the result with `'token' in result`. |

### Challenge and verification

| Method | Purpose |
| --- | --- |
| `push(userId, purpose = 'login')` | Issue a code and send it. |
| `pull(chatId)` | The user asked the bot for one; purpose `on_demand`. |
| `verify(userId, code, purpose = 'login')` | Check a code. |

Neither challenge method returns the code, so both results are safe to
`JSON.stringify` into a response.

`purpose` names the step a code authorises and is checked on every
verification:

```ts
await tfa.push(user.id, 'withdrawal')
// ...
await tfa.verify(user.id, code, 'withdrawal')   // a login code will not pass
```

There is no "match anything" value, and the default is `login` on both sides
rather than a wildcard. Exported constants: `PURPOSE_LOGIN`,
`PURPOSE_ON_DEMAND`, `PURPOSE_REPLACE`, `PURPOSE_UNLINK`. A code the user
fetched with `/code` carries `on_demand` and satisfies any purpose, which is
what keeps `/code` usable for confirming an unlink.

### State and removal

| Method | Purpose |
| --- | --- |
| `isLinked(userId)` | Verified link present. |
| `identity(userId)` / `identityForChat(chatId)` | The binding, either direction. |
| `unlink(userId, code)` | Remove, with proof under purpose `unlink`. |
| `unlinkAfterExternalProof(userId, reason)` | Remove, when another factor proved it. |

`error` on a failed result is an `ErrorCode` — the protocol's shared strings
(`not_linked`, `cooldown`, `invalid`, …). `errorMessages[code]` gives text safe
to show a user.

---

## Exports

| Export | What it is |
| --- | --- |
| `TelegramTwoFactor` | The protocol. |
| `Config` | Validated configuration, plus `fromEnv`. |
| `MemoryCodeStore`, `MemoryIdentityStore` | In-process, for tests. |
| `RedisCodeStore` | Works with node-redis and ioredis (`dialect` option). Requires `GETDEL` or `EVAL`. |
| `FetchTelegramClient` | Telegram over global `fetch`. |
| `DefaultMessages`, `escapeHtml` | Bot copy, and the escaper to use if you write your own. |
| `WebhookVerifier`, `SECRET_HEADER`, `TELEGRAM_RANGES` | Webhook authentication. |
| `UpdateHandler` | Command dispatch. |
| `CodeGenerator`, `CodeHasher` | CSPRNG codes; HMAC + `timingSafeEqual`. |
| `FrozenClock` | A clock you control, for testing expiry without sleeping. |
| `isVerified` | The link-is-real check, exported so your own code uses the same rule. |

All types are exported: `Identity`, `CodeStore`, `IdentityStore`,
`TelegramClient`, `Messages`, `Logger`, `Clock`, `ChallengeResult`,
`VerificationResult`, `LinkRequest`, `LinkResult`, `TelegramUpdate`.

---

## Testing against it

```ts
import { FrozenClock, MemoryCodeStore, MemoryIdentityStore } from '@kampe/telegram-2fa'

const clock = new FrozenClock()
const tfa = new TelegramTwoFactor({
  config,
  store: new MemoryCodeStore(clock),
  identities: new MemoryIdentityStore(clock),
  telegram: fakeClient,        // record what it was asked to send
  messages: new DefaultMessages(),
  clock,
})

await tfa.push('user-1')
clock.advance(301)
// → expired, with no waiting
```

Because the library never returns the code, read it back out of the message your
fake captured — which is also a neat proof that it is not leaking anywhere else.

---

### Why `CodeStore` has five methods

`take` and `add` are not a convenience. Single use and the attempt budget are
read-modify-write sequences, so built from get-check-delete they race: two
verifications arriving together both read the live record, both match, and both
succeed, while the attempt counter loses increments to the same lost update.

`take` is an atomic get-and-delete (Redis `GETDEL`, or `EVAL` on older servers);
`add` is an atomic set-if-absent that reports whether it stored, which makes the
cooldown and the webhook claim a reservation exactly one caller can win.

`RedisCodeStore` resolves its atomic primitive at construction and throws if the
client offers neither, rather than silently racing under load.

`IdentityStore` has one mutating method, `transition`, for a related reason: a
`link`/`unlink` pair invites read-then-write, and the window between validating
a replacement token and writing the binding is where that token outlives the
enrollment it proved. Hand the store the generation you expect and let it decide.

## Requirements

Node 18 or newer, for `fetch` and `AbortSignal.timeout`. Pass `fetchImpl` to
`FetchTelegramClient` to supply your own.

A store with atomic get-and-delete and set-if-absent. Redis 6.2+ has `GETDEL`;
older servers are handled through `EVAL`.

## Tests

```bash
npm install
npm test
```

135 tests written clause by clause against the specification, including the
cross-language fixtures in `/conformance` that the PHP package also reads, and
three kinds of concurrency test:

- `memory-store.test.ts` — `Promise.all` against the **shipped** stores, with no
  wrapper. This is the one that matters: the earlier suite tested races only
  through a test double that opened the window by hand, which proved the core
  coped when a race happened and nothing about whether the store prevented one.
  It did not.
- `concurrency.test.ts` — the core's handling of an interleaving, through that
  double
- `transition-race.test.ts` — enrollment transitions against recovery

Each protection has been checked by removing it and confirming the matching test
fails.
