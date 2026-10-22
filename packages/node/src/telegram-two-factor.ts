import { CodeGenerator, CodeHasher } from './codes.js'
import { Config } from './config.js'
import {
  type Clock,
  type CodeStore,
  type Identity,
  type IdentityStore,
  type Logger,
  type Messages,
  type TelegramClient,
  isVerified,
  nullLogger,
  systemClock,
} from './contracts.js'
import { ChatAlreadyLinked, ErrorCode } from './errors.js'

export interface ChallengeResult {
  ok: boolean
  error?: ErrorCode
  /** Unix seconds at which the issued code stops being accepted. */
  expiresAt?: number
  /** Unix seconds at which another code may be requested. */
  nextSendAt?: number
}

export interface VerificationResult {
  ok: boolean
  error?: ErrorCode
  attemptsRemaining?: number
}

export interface LinkRequest {
  /** A deeplink nonce, or a short code for the paste flow. */
  token: string
  expiresAt: number
  /** t.me deeplink, present only when the bot username is known. */
  url: string | null
}

export interface LinkResult {
  ok: boolean
  error?: ErrorCode
  identity?: Identity
}

interface CodeRecord {
  hash: string
  expiresAt: number
  attempts: number
  purpose: string
}

export interface TelegramTwoFactorOptions {
  config: Config
  store: CodeStore
  identities: IdentityStore
  telegram: TelegramClient
  messages: Messages
  clock?: Clock
  logger?: Logger
  codes?: CodeGenerator
  hasher?: CodeHasher
}

/**
 * Telegram as a second authentication factor.
 *
 * The whole protocol with no framework underneath it: linking (two flows),
 * challenge (two directions), verification, unlinking. Everything it touches
 * arrives through an interface, so the same class runs on Redis and Postgres, on
 * Prisma and Drizzle, or on maps in a test.
 *
 * @see SPEC.md for the normative protocol this implements.
 */
export class TelegramTwoFactor {
  readonly config: Config

  private readonly store: CodeStore
  private readonly identities: IdentityStore
  private readonly telegram: TelegramClient
  private readonly messages: Messages
  private readonly clock: Clock
  private readonly logger: Logger
  private readonly codes: CodeGenerator
  private readonly hasher: CodeHasher

  constructor(options: TelegramTwoFactorOptions) {
    this.config = options.config
    this.store = options.store
    this.identities = options.identities
    this.telegram = options.telegram
    this.messages = options.messages
    this.clock = options.clock ?? systemClock
    this.logger = options.logger ?? nullLogger
    this.codes = options.codes ?? new CodeGenerator()
    this.hasher =
      options.hasher ?? new CodeHasher(this.config.hashAlgorithm, this.config.hashPepper)
  }

  // --------------------------------------------------------------- identity

  /** Whether this account has a proven Telegram second factor. */
  async isLinked(userId: string): Promise<boolean> {
    return isVerified(await this.identities.findByUserId(userId))
  }

  async identity(userId: string): Promise<Identity | null> {
    return this.identities.findByUserId(userId)
  }

  /** The identity behind a chat, for the webhook side of the protocol. */
  async identityForChat(chatId: string): Promise<Identity | null> {
    return this.identities.findByChatId(chatId)
  }

  // ---------------------------------------------------------------- linking

  /**
   * Begin the deeplink flow: mint a nonce bound to this account.
   *
   * Show the returned url as a button, or as a QR code when the user is at a
   * desktop with Telegram on their phone. The token is bound to the account
   * before it reaches Telegram, so there is no window in which it is valid for
   * whoever happens to present it - which is what makes this preferable to the
   * paste flow.
   *
   * Minting for an already-linked account is harmless, so this does not check;
   * the check happens in completeDeepLink where acting on it matters.
   */
  async startDeepLink(userId: string): Promise<LinkRequest> {
    const token = this.codes.deepLinkToken()
    const expiresAt = this.clock.now() + this.config.linkTtl

    await this.store.put(
      this.config.key('link', this.hasher.hash(token)),
      { userId, expiresAt },
      this.config.linkTtl,
    )

    this.logger.info('telegram-2fa: deeplink issued', { userId })

    return { token, expiresAt, url: this.config.deepLinkUrl(token) }
  }

  /** Finish the deeplink flow, from the /start payload in a webhook update. */
  async completeDeepLink(token: string, chatId: string): Promise<LinkResult> {
    const key = this.config.key('link', this.hasher.hash(token))
    const record = (await this.store.get(key)) as { userId?: string; expiresAt?: number } | null

    if (record == null || typeof record.userId !== 'string') {
      this.logger.warn('telegram-2fa: deeplink token not resolvable', { chatId })
      return { ok: false, error: ErrorCode.InvalidToken }
    }

    if ((record.expiresAt ?? 0) < this.clock.now()) {
      await this.store.forget(key)
      return { ok: false, error: ErrorCode.InvalidToken }
    }

    // Single use, burned before the attempt rather than after: a token that
    // survives a failed attempt can be retried by anyone who saw it, and one
    // that survives a successful attempt can be replayed.
    await this.store.forget(key)

    return this.bind(record.userId, chatId)
  }

  /** Begin the paste flow, from the bot side: mint a code bound to this chat. */
  async startPasteLink(chatId: string): Promise<LinkRequest> {
    const code = this.codes.linkCode(this.config.linkCodeLength)
    const expiresAt = this.clock.now() + this.config.linkTtl

    await this.store.put(
      this.config.key('link', this.hasher.hash(code)),
      { chatId, expiresAt },
      this.config.linkTtl,
    )

    this.logger.info('telegram-2fa: paste link code issued')

    return { token: code, expiresAt, url: null }
  }

  /**
   * Finish the paste flow, from an authenticated page in your application.
   *
   * Two things this cannot check are the caller's: that userId comes from the
   * session rather than the request body, and that the endpoint is rate-limited.
   * Without the rate limit the attempt budget on this flow is unbounded, and
   * link codes share one namespace across all users.
   */
  async completePasteLink(userId: string, code: string): Promise<LinkResult> {
    const key = this.config.key('link', this.hasher.hash(code.trim().toUpperCase()))
    const record = (await this.store.get(key)) as { chatId?: string; expiresAt?: number } | null

    if (record == null || typeof record.chatId !== 'string') {
      this.logger.warn('telegram-2fa: paste code not resolvable', { userId })
      return { ok: false, error: ErrorCode.InvalidToken }
    }

    if ((record.expiresAt ?? 0) < this.clock.now()) {
      await this.store.forget(key)
      return { ok: false, error: ErrorCode.InvalidToken }
    }

    await this.store.forget(key)

    return this.bind(userId, record.chatId)
  }

  /** Record the binding, refusing anything that would create a shared factor. */
  private async bind(userId: string, chatId: string): Promise<LinkResult> {
    const existingForUser = await this.identities.findByUserId(userId)

    if (isVerified(existingForUser)) {
      // Re-presenting the same chat is a double submit, not a conflict.
      if (existingForUser!.chatId === chatId) {
        return { ok: true, identity: existingForUser! }
      }

      return { ok: false, error: ErrorCode.AlreadyLinked }
    }

    const existingForChat = await this.identities.findByChatId(chatId)

    if (existingForChat != null && existingForChat.userId !== userId) {
      this.logger.warn('telegram-2fa: chat already linked to another account', { userId })
      return { ok: false, error: ErrorCode.AlreadyLinked }
    }

    try {
      const identity = await this.identities.link(userId, chatId)
      this.logger.info('telegram-2fa: linked', { userId })

      return { ok: true, identity }
    } catch (error) {
      // The store's uniqueness constraint caught what the checks above raced
      // past. Two simultaneous links of one chat land here.
      if (error instanceof ChatAlreadyLinked) {
        return { ok: false, error: ErrorCode.AlreadyLinked }
      }

      throw error
    }
  }

  // -------------------------------------------------------------- challenge

  /**
   * Push direction: issue a code and send it to the linked chat.
   *
   * The code is not in the return value. It is generated, hashed into the store,
   * handed to Telegram and dropped, so the result can go straight into an HTTP
   * response.
   *
   * @param purpose Recorded with the code and checked on verification, so a
   *                code issued for one step cannot prove another.
   */
  async push(userId: string, purpose = 'login'): Promise<ChallengeResult> {
    const identity = await this.identities.findByUserId(userId)

    if (!isVerified(identity)) {
      return { ok: false, error: ErrorCode.NotLinked }
    }

    const blocked = await this.cooldownRemaining(userId)

    if (blocked !== null) {
      return { ok: false, error: ErrorCode.Cooldown, nextSendAt: blocked }
    }

    const code = await this.issue(userId, purpose)
    const sent = await this.telegram.sendMessage(
      identity!.chatId,
      this.messages.code(code, this.config.codeTtl),
    )

    if (!sent) {
      // Drop the code rather than leaving one live that the user never
      // received, which would strand the account until the cooldown expires.
      await this.clearPending(userId)
      this.logger.error('telegram-2fa: delivery failed', { userId })

      return { ok: false, error: ErrorCode.SendFailed }
    }

    this.logger.info('telegram-2fa: code sent', { userId, purpose })

    return {
      ok: true,
      expiresAt: this.clock.now() + this.config.codeTtl,
      nextSendAt: this.clock.now() + this.config.cooldown,
    }
  }

  /**
   * Pull direction: the user asked the bot for a code.
   *
   * Writes the same store key as push, so one verification call accepts a code
   * from either direction - see the single-key rule in SPEC.md section 4.
   */
  async pull(chatId: string, purpose = 'on_demand'): Promise<ChallengeResult> {
    const identity = await this.identities.findByChatId(chatId)

    if (!isVerified(identity)) {
      return { ok: false, error: ErrorCode.NotLinked }
    }

    const blocked = await this.cooldownRemaining(identity!.userId)

    if (blocked !== null) {
      return { ok: false, error: ErrorCode.Cooldown, nextSendAt: blocked }
    }

    const code = await this.issue(identity!.userId, purpose)
    const sent = await this.telegram.sendMessage(
      chatId,
      this.messages.code(code, this.config.codeTtl),
    )

    if (!sent) {
      await this.clearPending(identity!.userId)
      return { ok: false, error: ErrorCode.SendFailed }
    }

    this.logger.info('telegram-2fa: code issued on demand', { userId: identity!.userId })

    return {
      ok: true,
      expiresAt: this.clock.now() + this.config.codeTtl,
      nextSendAt: this.clock.now() + this.config.cooldown,
    }
  }

  /**
   * Generate a code, store its hash, arm the cooldown.
   *
   * Returns the plaintext to exactly one caller, which sends it and discards it.
   */
  private async issue(userId: string, purpose: string): Promise<string> {
    const code = this.codes.twoFactorCode(this.config.codeLength)
    const now = this.clock.now()

    const record: CodeRecord = {
      hash: this.hasher.hash(code),
      expiresAt: now + this.config.codeTtl,
      attempts: 0,
      purpose,
    }

    await this.store.put(this.config.key('code', userId), record, this.config.codeTtl)
    await this.store.put(
      this.config.key('cooldown', userId),
      now + this.config.cooldown,
      this.config.cooldown,
    )

    return code
  }

  private async cooldownRemaining(userId: string): Promise<number | null> {
    const value = await this.store.get(this.config.key('cooldown', userId))
    const nextSendAt = Number(value)

    if (value == null || Number.isNaN(nextSendAt)) {
      return null
    }

    return nextSendAt > this.clock.now() ? nextSendAt : null
  }

  private async clearPending(userId: string): Promise<void> {
    await this.store.forget(this.config.key('code', userId))
    await this.store.forget(this.config.key('cooldown', userId))
  }

  // ----------------------------------------------------------- verification

  /**
   * Check a submitted code.
   *
   * Single use on success, attempt-budgeted on failure, constant-time
   * throughout. When purpose is given it must match what the code was issued
   * for.
   */
  async verify(userId: string, code: string, purpose?: string): Promise<VerificationResult> {
    const key = this.config.key('code', userId)
    const record = (await this.store.get(key)) as CodeRecord | null

    if (record == null || typeof record.hash !== 'string') {
      return { ok: false, error: ErrorCode.Expired }
    }

    const attempts = Number(record.attempts ?? 0)

    if (attempts >= this.config.maxAttempts) {
      await this.store.forget(key)
      return { ok: false, error: ErrorCode.TooManyAttempts, attemptsRemaining: 0 }
    }

    if (Number(record.expiresAt ?? 0) < this.clock.now()) {
      await this.store.forget(key)
      return { ok: false, error: ErrorCode.Expired }
    }

    // A code minted to confirm a login should not also confirm a withdrawal.
    // Count the mismatch as an attempt rather than a free retry.
    if (purpose !== undefined && record.purpose !== purpose) {
      return this.recordFailedAttempt(key, record, attempts)
    }

    if (!this.hasher.matches(record.hash, code.trim())) {
      return this.recordFailedAttempt(key, record, attempts)
    }

    await this.store.forget(key)
    this.logger.info('telegram-2fa: verified', { userId, purpose: record.purpose })

    return { ok: true }
  }

  private async recordFailedAttempt(
    key: string,
    record: CodeRecord,
    attempts: number,
  ): Promise<VerificationResult> {
    const spent = attempts + 1
    const remaining = this.config.maxAttempts - spent

    if (remaining <= 0) {
      await this.store.forget(key)
      return { ok: false, error: ErrorCode.TooManyAttempts, attemptsRemaining: 0 }
    }

    // Re-store under the code's own remaining lifetime. Writing it back with a
    // fresh full TTL would let an attacker keep a code alive indefinitely by
    // guessing wrong, removing the time limit altogether.
    await this.store.put(
      key,
      { ...record, attempts: spent },
      Math.max(1, record.expiresAt - this.clock.now()),
    )

    return { ok: false, error: ErrorCode.Invalid, attemptsRemaining: remaining }
  }

  // ------------------------------------------------------------- unlinking

  /**
   * Remove the factor, proving possession of it first.
   *
   * Unlinking is the step an attacker with a stolen session but no phone needs,
   * so it demands the same proof as any other protected action.
   */
  async unlink(userId: string, code: string): Promise<VerificationResult> {
    const identity = await this.identities.findByUserId(userId)

    if (!isVerified(identity)) {
      return { ok: false, error: ErrorCode.NotLinked }
    }

    const result = await this.verify(userId, code)

    if (!result.ok) {
      return result
    }

    await this.detach(identity!)

    return { ok: true }
  }

  /**
   * Remove the factor when another factor has already proved the request.
   *
   * For recovery paths: the user still has their authenticator, or passed an
   * out-of-band check, but has lost the Telegram account. The caller takes
   * responsibility for that proof - this method performs none.
   */
  async unlinkAfterExternalProof(userId: string, reason: string): Promise<boolean> {
    const identity = await this.identities.findByUserId(userId)

    if (identity == null) {
      return false
    }

    await this.detach(identity)
    this.logger.warn('telegram-2fa: unlinked via external proof', { userId, reason })

    return true
  }

  private async detach(identity: Identity): Promise<void> {
    await this.identities.unlink(identity.userId)
    await this.clearPending(identity.userId)

    // Best effort: the user should hear that their factor was removed even if,
    // especially if, they did not do it themselves.
    await this.telegram.sendMessage(
      identity.chatId,
      this.messages.unlinked(this.config.appName),
    )

    this.logger.info('telegram-2fa: unlinked', { userId: identity.userId })
  }
}
