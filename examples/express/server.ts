/**
 * A complete Express integration.
 *
 * Four endpoints and a webhook, which is the whole protocol:
 *
 *   POST /telegram/webhook        Telegram calls this. Authenticated by secret token.
 *   GET  /settings/telegram       start linking, returns a t.me URL
 *   POST /settings/telegram/code  paste-flow completion
 *   POST /auth/2fa/send           push a challenge
 *   POST /auth/2fa/verify         verify a submitted code
 *
 * Run with: npx tsx server.ts
 */

import express, { type NextFunction, type Request, type Response } from 'express'
import rateLimit from 'express-rate-limit'
import {
  ChatAlreadyLinked,
  Config,
  DefaultMessages,
  FetchTelegramClient,
  type Identity,
  type IdentityStore,
  MemoryCodeStore,
  SECRET_HEADER,
  TelegramTwoFactor,
  UpdateHandler,
  WebhookVerifier,
} from '@kampe/telegram-2fa'

// ---------------------------------------------------------------- your data

/**
 * The only adapter you have to write. Four methods over your own users table.
 *
 * This example keeps users in a Map; the real thing is four queries. The
 * uniqueness check in link() must be backed by a unique index on the chat id
 * column — two concurrent links both pass an application-level check and only
 * one can pass an index.
 */
class UserIdentityStore implements IdentityStore {
  private users = new Map<string, { email: string; chatId: string | null; linkedAt: number | null }>(
    [['user-1', { email: 'ada@example.com', chatId: null, linkedAt: null }]],
  )

  async findByUserId(userId: string): Promise<Identity | null> {
    const user = this.users.get(userId)

    if (user?.chatId == null) {
      return null
    }

    return { userId, chatId: user.chatId, linkedAt: user.linkedAt }
  }

  async findByChatId(chatId: string): Promise<Identity | null> {
    for (const [userId, user] of this.users) {
      if (user.chatId === chatId) {
        return { userId, chatId, linkedAt: user.linkedAt }
      }
    }

    return null
  }

  async link(userId: string, chatId: string): Promise<Identity> {
    const taken = await this.findByChatId(chatId)

    if (taken !== null && taken.userId !== userId) {
      // In a real store this is the unique-index violation, translated.
      throw new ChatAlreadyLinked('That chat is already a second factor for another account.')
    }

    const user = this.users.get(userId)

    if (user === undefined) {
      throw new Error(`Unknown user ${userId}`)
    }

    user.chatId = chatId
    user.linkedAt = Math.floor(Date.now() / 1000)

    return { userId, chatId, linkedAt: user.linkedAt }
  }

  async unlink(userId: string): Promise<void> {
    const user = this.users.get(userId)

    if (user !== undefined) {
      user.chatId = null
      user.linkedAt = null
    }
  }

  /** Used for the label in the link confirmation message. */
  async labelFor(userId: string): Promise<string> {
    const email = this.users.get(userId)?.email ?? 'your account'

    // Masked, because this message sits in a chat history.
    return email.replace(/^(.)[^@]*(@.*)$/, '$1***$2')
  }
}

// ------------------------------------------------------------------ wiring

const identities = new UserIdentityStore()
const config = Config.fromEnv()
const messages = new DefaultMessages()
const telegram = new FetchTelegramClient({ botToken: config.botToken })

// Use Redis in production: RedisCodeStore. A per-process store means a code
// issued by one worker is invisible to the next.
const store = new MemoryCodeStore()

const tfa = new TelegramTwoFactor({ config, store, identities, telegram, messages })
const verifier = new WebhookVerifier(config)

const handler = new UpdateHandler({
  tfa,
  config,
  store,
  telegram,
  messages,
  accountLabel: (userId) => identities.labelFor(userId),
})

const app = express()

/** Stand-in for your real session middleware. */
function currentUser(req: Request): string {
  const userId = req.header('X-Demo-User')

  if (userId === undefined) {
    throw new Error('not signed in')
  }

  return userId
}

// ------------------------------------------------------------------ webhook

/**
 * Authenticated by the secret token, which is why it does not need — and must
 * not have — CSRF protection: Telegram has no session and no token to send.
 */
app.post('/telegram/webhook', express.json({ limit: '64kb' }), async (req, res) => {
  if (!verifier.accepts(req.get(SECRET_HEADER), req.ip)) {
    // 403, empty. Telegram does not retry a 403, and a forger learns nothing.
    return res.sendStatus(403)
  }

  try {
    await handler.handle(req.body)
  } catch (error) {
    // Log the failure, never the payload: the payload contains the codes.
    console.error('telegram-2fa: handler failed', {
      error: error instanceof Error ? error.message : 'unknown',
      updateId: req.body?.update_id,
    })
  }

  // Always 200. A non-2xx makes Telegram retry and queue every later update
  // behind this one.
  res.json({ ok: true })
})

// Everything below is your own API surface.
app.use(express.json())

// --------------------------------------------------------------- linking

app.get('/settings/telegram', async (req, res) => {
  const userId = currentUser(req)

  if (await tfa.isLinked(userId)) {
    return res.json({ linked: true })
  }

  const link = await tfa.startDeepLink(userId)

  // Render url as a button, and as a QR code for users whose Telegram is on
  // another device. The browser learns nothing when the user taps it, so poll
  // this endpoint, or push over a websocket, to notice the link completing.
  res.json({ linked: false, url: link.url, expiresAt: link.expiresAt })
})

app.post(
  '/settings/telegram/code',
  // The paste flow's codes share one namespace across all users, so this limit
  // is part of the security of the flow, not a nicety.
  rateLimit({ windowMs: 60_000, limit: 5 }),
  async (req, res) => {
    const userId = currentUser(req)
    const result = await tfa.completePasteLink(userId, String(req.body.code ?? ''))

    res.status(result.ok ? 200 : 400).json(result)
  },
)

// --------------------------------------------------------------- challenge

app.post('/auth/2fa/send', rateLimit({ windowMs: 60_000, limit: 5 }), async (req, res) => {
  const result = await tfa.push(currentUser(req), String(req.body.purpose ?? 'login'))

  // Safe to return whole: the result never contains the code.
  res.status(result.ok ? 200 : 429).json(result)
})

app.post('/auth/2fa/verify', rateLimit({ windowMs: 60_000, limit: 10 }), async (req, res) => {
  // The purpose must match what the code was issued for. Take it from the
  // server-side context of the action being confirmed, never from the request
  // body as it is here — a client that chooses its own purpose can ask for the
  // one its code happens to carry.
  const result = await tfa.verify(
    currentUser(req),
    String(req.body.code ?? ''),
    String(req.body.purpose ?? 'login'),
  )

  if (!result.ok) {
    return res.status(400).json(result)
  }

  // Mark the session as having passed the second factor here.
  res.json({ ok: true })
})

// --------------------------------------------------------------- unlinking

app.post('/settings/telegram/unlink', async (req, res) => {
  // Proof of the factor is required to remove it: unlinking from a session
  // alone is exactly the move an attacker with a stolen session makes.
  //
  // Send the user a code with push(userId, PURPOSE_UNLINK) first, or let them
  // fetch one with /code — on-demand codes satisfy any purpose.
  const result = await tfa.unlink(currentUser(req), String(req.body.code ?? ''))

  res.status(result.ok ? 200 : 400).json(result)
})

// ------------------------------------------------------- moving to a new chat

/**
 * The user has a new Telegram account.
 *
 * Linking never silently moves a verified binding, so this costs a code from
 * the chat being replaced. Issue it with push(userId, PURPOSE_REPLACE).
 */
app.post('/settings/telegram/replace', rateLimit({ windowMs: 60_000, limit: 5 }), async (req, res) => {
  const result = await tfa.startChatReplacement(
    currentUser(req),
    String(req.body.code ?? ''),
  )

  if (!('token' in result)) {
    return res.status(400).json(result)
  }

  // Show this the same way as a first-time link: a button, and a QR code for a
  // user whose new Telegram is on another device.
  res.json({ url: result.url, expiresAt: result.expiresAt })
})

app.listen(3000, () => {
  console.log('listening on http://localhost:3000')
})
