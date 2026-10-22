import { randomBytes, timingSafeEqual } from 'node:crypto'
import { CodeGenerator, CodeHasher } from './codes.js'
import { Config } from './config.js'
import {
  ANY_GENERATION,
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

/**
 * The stored challenge record.
 *
 * snake_case because these field names are the wire format of SPEC.md section
 * 9, shared with every other implementation. Using camelCase here would mean
 * the PHP and Node packages could not read each other's records, which is the
 * interoperability the repository claims.
 */
interface CodeRecord {
  hash: string
  expires_at: number
  attempts: number
  purpose: string
  /**
   * The enrollment this challenge belongs to. Verification refuses a challenge
   * from a superseded enrollment, which is what stops a code outliving the chat
   * it was sent to.
   */
  generation: string | null
  /**
   * Identifies this particular challenge, so a cleanup for a failed delivery
   * can tell its own code from a newer one.
   */
  challenge_id: string
}

/** The stored link record. snake_case for the same reason. */
interface LinkRecord {
  user_id?: string
  chat_id?: string
  expires_at: number
  replace?: boolean
  generation?: string | null
}

/**
 * Constant-time comparison of two equal-purpose strings.
 *
 * Generations are not secrets in the way a code is, but they are compared on
 * paths that also handle codes, and a length-and-content comparison costs
 * nothing here.
 */
function timingSafeStringEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')

  return left.length === right.length && timingSafeEqual(left, right)
}

/** The default purpose, for an ordinary sign-in. */
export const PURPOSE_LOGIN = 'login'

/**
 * The purpose of a code the user fetched themselves with /code.
 *
 * Such a code carries no knowledge of what it is about to authorise, so it
 * satisfies any requested purpose. That is sound because the user asked for it
 * deliberately - nothing the application did caused it to exist.
 */
export const PURPOSE_ON_DEMAND = 'on_demand'

/** Proving the current factor before rebinding to a new chat. */
export const PURPOSE_REPLACE = 'replace'

/** Proving the current factor before removing it. */
export const PURPOSE_UNLINK = 'unlink'

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

    const record: LinkRecord = { user_id: userId, expires_at: expiresAt }

    await this.store.put(
      this.config.key('link', this.hasher.hash(token)),
      record,
      this.config.linkTtl,
    )

    this.logger.info('telegram-2fa: deeplink issued', { userId })

    return { token, expiresAt, url: this.config.deepLinkUrl(token) }
  }

  /** Finish the deeplink flow, from the /start payload in a webhook update. */
  async completeDeepLink(token: string, chatId: string): Promise<LinkResult> {
    // Single use, and taken atomically: a token read now and deleted later can
    // be resolved twice by two concurrent /start messages, and a token that
    // survives a failed attempt can be retried by anyone who saw it - and it
    // travelled through a chat, so others may have.
    const record = (await this.store.take(
      this.config.key('link', this.hasher.hash(token)),
    )) as LinkRecord | null

    if (record == null || typeof record.user_id !== 'string') {
      this.logger.warn('telegram-2fa: deeplink token not resolvable', { chatId })
      return { ok: false, error: ErrorCode.InvalidToken }
    }

    if ((record.expires_at ?? 0) < this.clock.now()) {
      return { ok: false, error: ErrorCode.InvalidToken }
    }

    const replace = record.replace === true

    // A replacement token carries authority over an existing factor, so it is
    // only valid against the binding whose possession was proved. If that
    // binding has since changed - recovered through support, unlinked, or
    // already replaced - the proof no longer refers to anything and the token
    // is void. Without this, a token minted before an account recovery still
    // moves the factor afterwards, which hands whoever holds it the new chat.
    const provenGeneration = typeof record.generation === 'string' ? record.generation : null

    if (replace && !(await this.generationIsCurrent(record.user_id, provenGeneration))) {
      this.logger.warn('telegram-2fa: stale replacement token rejected', {
        userId: record.user_id,
      })

      return { ok: false, error: ErrorCode.InvalidToken }
    }

    return this.bind(record.user_id, chatId, replace, provenGeneration)
  }

  /**
   * Whether the enrollment a replacement token was issued against is current.
   *
   * Advisory: it gives a clear error early. The binding write repeats it as a
   * condition, which is what actually makes it safe, because a recovery can
   * land between this read and that write.
   */
  private async generationIsCurrent(userId: string, generation: unknown): Promise<boolean> {
    if (typeof generation !== 'string' || generation === '') {
      return false
    }

    const identity = await this.identities.findByUserId(userId)

    if (!isVerified(identity) || identity!.generation === null) {
      return false
    }

    return timingSafeStringEqual(identity!.generation, generation)
  }

  /**
   * Whether a challenge belongs to the account's current enrollment.
   *
   * A challenge issued before the generation existed (a row migrated from an
   * older version) is accepted only while the account has no generation at all,
   * so upgrading does not invalidate codes in flight.
   */
  private async generationMatches(userId: string, generation: unknown): Promise<boolean> {
    const current = (await this.identities.findByUserId(userId))?.generation ?? null

    if (current === null) {
      return generation === null || generation === undefined
    }

    return typeof generation === 'string' && timingSafeStringEqual(current, generation)
  }

  /**
   * A fresh enrollment generation.
   *
   * Random rather than a counter: nothing needs ordering, only inequality, and
   * a random value cannot be predicted from the ones before it.
   */
  private nextGeneration(): string {
    return randomBytes(16).toString('hex')
  }

  /**
   * Begin moving the factor to a different Telegram account.
   *
   * Linking never silently moves a verified binding, because a flow that did
   * would let anyone holding a session attach their own chat to the account. So
   * replacement is explicit and costs a code from the chat being replaced:
   * prove the current factor here, then resolve the returned token from the new
   * chat.
   *
   * A user who has lost the old chat entirely cannot do this, and belongs in
   * unlinkAfterExternalProof() instead.
   *
   * @returns the link request on success, or the verification failure that
   *          stopped it. Narrow with `'token' in result`.
   */
  async startChatReplacement(
    userId: string,
    code: string,
  ): Promise<LinkRequest | VerificationResult> {
    const identity = await this.identities.findByUserId(userId)

    if (!isVerified(identity)) {
      return { ok: false, error: ErrorCode.NotLinked }
    }

    const proof = await this.verify(userId, code, PURPOSE_REPLACE)

    if (!proof.ok) {
      return proof
    }

    // Re-read: the enrollment can have moved while the code was being checked,
    // and the token must reference the generation current when it is minted.
    let current = await this.identities.findByUserId(userId)

    if (!isVerified(current)) {
      return { ok: false, error: ErrorCode.NotLinked }
    }

    if (current!.generation === null) {
      // A row enrolled before the generation existed. Give it one before
      // issuing authority over it, so the token has something concrete to
      // reference and upgrading does not produce unvalidatable tokens.
      current = await this.identities.transition(
        userId,
        current!.chatId,
        null,
        this.nextGeneration(),
      )

      if (current === null) {
        return { ok: false, error: ErrorCode.NotLinked }
      }
    }

    const token = this.codes.deepLinkToken()
    const expiresAt = this.clock.now() + this.config.linkTtl

    // The replace mark lives on the stored token, not on the call that resolves
    // it. Taking it from the resolution side would make the proof above
    // skippable by presenting an ordinary token.
    //
    // The generation pins the authority to the enrollment just proved. The
    // binding write repeats this as its CAS expectation, so a recovery landing
    // between here and there makes that write fail rather than overwrite the
    // recovered enrollment.
    const record: LinkRecord = {
      user_id: userId,
      expires_at: expiresAt,
      replace: true,
      generation: current!.generation,
    }

    await this.store.put(
      this.config.key('link', this.hasher.hash(token)),
      record,
      this.config.linkTtl,
    )

    this.logger.info('telegram-2fa: chat replacement authorised', { userId })

    return { token, expiresAt, url: this.config.deepLinkUrl(token) }
  }

  /** Begin the paste flow, from the bot side: mint a code bound to this chat. */
  async startPasteLink(chatId: string): Promise<LinkRequest> {
    const code = this.codes.linkCode(this.config.linkCodeLength)
    const expiresAt = this.clock.now() + this.config.linkTtl

    const record: LinkRecord = { chat_id: chatId, expires_at: expiresAt }

    await this.store.put(
      this.config.key('link', this.hasher.hash(code)),
      record,
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
    const record = (await this.store.take(
      this.config.key('link', this.hasher.hash(code.trim().toUpperCase())),
    )) as LinkRecord | null

    if (record == null || typeof record.chat_id !== 'string') {
      this.logger.warn('telegram-2fa: paste code not resolvable', { userId })
      return { ok: false, error: ErrorCode.InvalidToken }
    }

    if ((record.expires_at ?? 0) < this.clock.now()) {
      return { ok: false, error: ErrorCode.InvalidToken }
    }

    return this.bind(userId, record.chat_id)
  }

  /**
   * Record the enrollment, as one conditional transition.
   *
   * Everything here hangs on handing the store an expectation rather than
   * reading state and then writing it. The validation in completeDeepLink
   * happens a moment earlier, and a recovery or a competing link can land in
   * between; passing the generation we believed was current means such a write
   * fails instead of overwriting whatever replaced it.
   */
  private async bind(
    userId: string,
    chatId: string,
    replace = false,
    provenGeneration: string | null = null,
  ): Promise<LinkResult> {
    const existing = await this.identities.findByUserId(userId)
    let replacing: Identity | null = null

    if (isVerified(existing)) {
      // Re-presenting the same chat is a double submit, not a conflict.
      if (existing!.chatId === chatId) {
        return { ok: true, identity: existing! }
      }

      if (!replace) {
        return { ok: false, error: ErrorCode.AlreadyLinked }
      }

      replacing = existing!
    }

    const expected = replace ? provenGeneration : (existing?.generation ?? null)
    const holder = await this.identities.findByChatId(chatId)

    if (holder !== null && holder.userId !== userId) {
      this.logger.warn('telegram-2fa: chat already linked to another account', { userId })

      return { ok: false, error: ErrorCode.AlreadyLinked }
    }

    let identity: Identity | null

    try {
      // One write. It either moves the enrollment or changes nothing, so a
      // replacement onto an unavailable chat - or one overtaken by a recovery -
      // leaves the existing enrollment exactly as it was, rather than stripping
      // the account of its second factor as a side effect of a failed request.
      identity = await this.identities.transition(
        userId,
        chatId,
        expected,
        this.nextGeneration(),
      )
    } catch (error) {
      // The store's uniqueness constraint caught what the check above raced
      // past. The loser's existing enrollment is untouched.
      if (error instanceof ChatAlreadyLinked) {
        return { ok: false, error: ErrorCode.AlreadyLinked }
      }

      throw error
    }

    if (identity === null) {
      // The enrollment changed under us. For a replacement that means the token
      // is stale; for a first link, that another request got there.
      this.logger.warn('telegram-2fa: enrollment changed during link', { userId, replace })

      return {
        ok: false,
        error: replace ? ErrorCode.InvalidToken : ErrorCode.AlreadyLinked,
      }
    }

    if (replacing !== null) {
      // Any code in flight was delivered to the chat that is no longer the
      // factor, so whoever still has that chat could use it. The generation has
      // already changed, so such a code is unusable even if this cleanup loses
      // a race; this merely stops it lingering.
      await this.clearPending(userId)

      // Afterwards, so a failed replacement never announces one. If the user
      // did not request this, that message is how they find out.
      await this.telegram.sendMessage(
        replacing.chatId ?? '',
        this.messages.unlinked(this.config.appName),
      )

      this.logger.info('telegram-2fa: factor replaced', { userId })

      return { ok: true, identity }
    }

    this.logger.info('telegram-2fa: linked', { userId })

    return { ok: true, identity }
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
  async push(userId: string, purpose: string = PURPOSE_LOGIN): Promise<ChallengeResult> {
    const identity = await this.identities.findByUserId(userId)

    if (!isVerified(identity)) {
      return { ok: false, error: ErrorCode.NotLinked }
    }

    const blocked = await this.reserveSend(userId)

    if (blocked !== null) {
      return { ok: false, error: ErrorCode.Cooldown, nextSendAt: blocked }
    }

    const challenge = await this.issue(userId, purpose, identity!.generation)
    const sent = await this.telegram.sendMessage(
      identity!.chatId ?? '',
      this.messages.code(challenge.code, this.config.codeTtl),
    )

    if (!sent) {
      // Drop the code rather than leaving one live that the user never
      // received, which would strand the account until the cooldown expires.
      // Conditionally, so a slow failure cannot delete a code issued after it.
      await this.discardChallenge(userId, challenge.challengeId)
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
  async pull(chatId: string, purpose: string = PURPOSE_ON_DEMAND): Promise<ChallengeResult> {
    const identity = await this.identities.findByChatId(chatId)

    if (!isVerified(identity)) {
      return { ok: false, error: ErrorCode.NotLinked }
    }

    const blocked = await this.reserveSend(identity!.userId)

    if (blocked !== null) {
      return { ok: false, error: ErrorCode.Cooldown, nextSendAt: blocked }
    }

    const challenge = await this.issue(identity!.userId, purpose, identity!.generation)
    const sent = await this.telegram.sendMessage(
      chatId,
      this.messages.code(challenge.code, this.config.codeTtl),
    )

    if (!sent) {
      await this.discardChallenge(identity!.userId, challenge.challengeId)
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
  private async issue(
    userId: string,
    purpose: string,
    generation: string | null,
  ): Promise<{ code: string; challengeId: string }> {
    const code = this.codes.twoFactorCode(this.config.codeLength)
    const challengeId = randomBytes(8).toString('hex')

    const record: CodeRecord = {
      // Bound to the account, so a digest lifted from the store cannot be
      // matched against another user's code.
      hash: this.hasher.hash(code, userId),
      expires_at: this.clock.now() + this.config.codeTtl,
      attempts: 0,
      purpose,
      generation,
      challenge_id: challengeId,
    }

    await this.store.put(this.config.key('code', userId), record, this.config.codeTtl)

    return { code, challengeId }
  }

  /**
   * Drop a challenge only if it is still the one we issued.
   *
   * A delivery failure must not delete a newer challenge. That is reachable: if
   * sending blocks past the cooldown, the user can be issued a fresh code
   * before this handler runs, and an unconditional delete would throw away a
   * code the user is holding.
   */
  private async discardChallenge(userId: string, challengeId: string): Promise<void> {
    const key = this.config.key('code', userId)
    const record = (await this.store.take(key)) as CodeRecord | null

    if (record === null) {
      return
    }

    if (record.challenge_id !== challengeId) {
      // Someone else's challenge. Put it back as we found it.
      await this.store.put(
        key,
        record,
        Math.max(1, (record.expires_at ?? 0) - this.clock.now()),
      )

      return
    }

    await this.store.forget(this.config.key('cooldown', userId))
  }

  /**
   * Reserve the right to send, atomically.
   *
   * Checking for a cooldown and then writing one is two operations, and two
   * challenges arriving together both see no cooldown and both send. add()
   * makes the write itself the check, so exactly one caller wins the window.
   *
   * @returns the timestamp another send becomes possible, when this caller lost
   * the reservation; null when it won.
   */
  private async reserveSend(userId: string): Promise<number | null> {
    const key = this.config.key('cooldown', userId)
    const nextSendAt = this.clock.now() + this.config.cooldown

    if (await this.store.add(key, nextSendAt, this.config.cooldown)) {
      return null
    }

    const held = Number(await this.store.get(key))

    // Fall back to the full cooldown if the value has gone between the failed
    // add and this read, rather than reporting a time in the past.
    return Number.isFinite(held) ? held : nextSendAt
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
   * throughout.
   *
   * `purpose` must match what the code was issued for, and defaults to
   * PURPOSE_LOGIN exactly as push() does. There is deliberately no way to skip
   * the check: a default of "compare against nothing" would mean the binding
   * does nothing unless every call site opts in, and the call site that forgets
   * is both invisible and the one that matters - a code issued to confirm a
   * sign-in approving a payout.
   */
  async verify(
    userId: string,
    code: string,
    purpose: string = PURPOSE_LOGIN,
  ): Promise<VerificationResult> {
    const key = this.config.key('code', userId)

    // Take the record, rather than read it and delete it later. Those are two
    // operations with a gap between them, and two verifications arriving
    // together both read the live record, both match, and both succeed - a
    // single-use code used twice, with the attempt counter losing increments to
    // the same race. Taking it means the winner holds the only copy: it either
    // consumes the code or writes it back with one more attempt spent, while a
    // concurrent caller finds nothing.
    const record = (await this.store.take(key)) as CodeRecord | null

    if (record == null || typeof record.hash !== 'string') {
      return { ok: false, error: ErrorCode.Expired }
    }

    const attempts = Number(record.attempts ?? 0)

    // The record is already gone in each of these branches, which is what we
    // want: a spent or expired code should not come back.
    if (attempts >= this.config.maxAttempts) {
      return { ok: false, error: ErrorCode.TooManyAttempts, attemptsRemaining: 0 }
    }

    if (Number(record.expires_at ?? 0) < this.clock.now()) {
      return { ok: false, error: ErrorCode.Expired }
    }

    // The enrollment this challenge belongs to must still be the current one.
    // Anything that changed it - a replacement, an unlink, a recovery - revoked
    // this challenge, and the record is already gone because we took it, so a
    // revoked challenge dies here rather than being restored.
    //
    // This check, not the cleanup in bind(), is what makes revocation sound:
    // cleanup races a concurrent verification, while this cannot.
    if (!(await this.generationMatches(userId, record.generation))) {
      this.logger.warn('telegram-2fa: challenge from a superseded enrollment', { userId })

      return { ok: false, error: ErrorCode.Expired }
    }

    // A code minted to confirm a login should not also confirm a withdrawal.
    // Count the mismatch as an attempt rather than a free retry, and report it
    // as `invalid`: telling the caller that a live code exists for some other
    // purpose is information it has not proved it should have.
    if (!this.purposeSatisfied(record.purpose, purpose)) {
      return this.recordFailedAttempt(key, record, attempts, userId)
    }

    if (!this.hasher.matches(record.hash, code.trim(), userId)) {
      return this.recordFailedAttempt(key, record, attempts, userId)
    }

    this.logger.info('telegram-2fa: verified', { userId, purpose: record.purpose })

    return { ok: true }
  }

  /**
   * Whether a stored code may be used for the purpose being requested.
   *
   * An on-demand code is general-purpose by default, because it cannot know
   * what it is for and the user asked for it deliberately. That is a policy
   * rather than a law: requesting a code does not prove intent to perform any
   * particular action, so an installation that wants privileged steps to issue
   * their own code can narrow it with onDemandSatisfies.
   */
  private purposeSatisfied(stored: string, requested: string): boolean {
    if (stored === requested) {
      return true
    }

    if (stored !== PURPOSE_ON_DEMAND) {
      return false
    }

    return (
      this.config.onDemandSatisfies === null ||
      this.config.onDemandSatisfies.includes(requested)
    )
  }

  private async recordFailedAttempt(
    key: string,
    record: CodeRecord,
    attempts: number,
    userId: string,
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
    //
    // A revocation can land between the take above and this write, so this
    // re-check keeps a dead challenge from being written back. It is
    // best-effort by nature - the window cannot be closed from here - and does
    // not need to be airtight, because verify() re-checks the generation before
    // accepting anything. A resurrected record is inert.
    if (await this.generationMatches(userId, record.generation)) {
      await this.store.put(
        key,
        { ...record, attempts: spent },
        Math.max(1, record.expires_at - this.clock.now()),
      )
    }

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

    // Under PURPOSE_UNLINK, so a code pushed for a login cannot remove the
    // factor. A code the user fetched with /code still works, because
    // on-demand codes are general-purpose.
    const result = await this.verify(userId, code, PURPOSE_UNLINK)

    if (!result.ok) {
      return result
    }

    if (!(await this.detach(identity!, identity!.generation))) {
      // The enrollment moved while we were verifying, so the code we just
      // accepted no longer refers to what is stored.
      return { ok: false, error: ErrorCode.Expired }
    }

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

    // Unconditional: the caller has proved identity by other means, and a
    // recovery must not be blocked by whatever the account's state is.
    await this.detach(identity, ANY_GENERATION)
    this.logger.warn('telegram-2fa: unlinked via external proof', { userId, reason })

    return true
  }

  /**
   * Remove the enrollment and revoke everything that referred to it.
   *
   * The generation is advanced even though no chat remains, which is the whole
   * reason it is stored separately from the chat id: a replacement token or a
   * challenge minted before this point stays void afterwards, and would
   * otherwise come back to life the moment the user links again.
   *
   * @param expected the generation the caller verified against, or
   *                 ANY_GENERATION for a recovery, where the caller has already
   *                 proved identity another way and must not be blocked by a
   *                 concurrent change
   * @returns whether the transition applied
   */
  private async detach(identity: Identity, expected: string | null): Promise<boolean> {
    const moved = await this.identities.transition(
      identity.userId,
      null,
      expected,
      this.nextGeneration(),
    )

    if (moved === null) {
      this.logger.warn('telegram-2fa: enrollment changed during unlink', {
        userId: identity.userId,
      })

      return false
    }

    await this.clearPending(identity.userId)

    // Best effort: the user should hear that their factor was removed even if,
    // especially if, they did not do it themselves.
    if (identity.chatId !== null) {
      await this.telegram.sendMessage(
        identity.chatId,
        this.messages.unlinked(this.config.appName),
      )
    }

    this.logger.info('telegram-2fa: unlinked', { userId: identity.userId })

    return true
  }
}
