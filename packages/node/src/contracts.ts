/**
 * Everything the library needs from the outside world.
 *
 * All four are small on purpose: an integration is four adapters, each a handful
 * of lines, rather than a framework to adopt.
 */

/**
 * An account's Telegram enrollment, as the identity store holds it.
 *
 * This represents the row rather than only the linked state, so an account that
 * has been unlinked still has an Identity - carrying no chat, but carrying the
 * generation. That is deliberate: revocation has to outlive the binding it
 * revokes, or a token minted before an unlink would come back to life when the
 * user links again.
 */
export interface Identity {
  userId: string
  /** The linked chat, or null when this account is not currently linked. */
  chatId: string | null
  /** Unix seconds when the link was proven, or null when it was not. */
  linkedAt: number | null
  /**
   * Opaque enrollment generation, changed by every transition.
   *
   * Null only for a row that has never been enrolled. Anything holding
   * authority over an enrollment records this value and is void once it
   * differs.
   */
  generation: string | null
}

/** Expectation meaning "whatever is there now", for recovery paths. */
export const ANY_GENERATION = '\u0000any'

/**
 * Only a verified link counts as a second factor.
 *
 * A record carrying a chat id with no timestamp is a link that was started and
 * never completed. Treating it as linked would let anyone who can write a chat
 * id into the record satisfy a challenge.
 */
export function isVerified(identity: Identity | null | undefined): boolean {
  return identity?.chatId != null && identity?.linkedAt != null
}

/**
 * Short-lived key/value storage with a TTL.
 *
 * Redis, Memcached, a Postgres table with an expires_at column - anything with
 * expiry. It holds code hashes, never plaintext codes.
 *
 * Two of the five methods must be atomic. They are not a convenience: a
 * verification built from get-check-forget is a time-of-check-to-time-of-use
 * race, and two requests arriving together both read the live record, both match
 * it, and both succeed - so a single-use code is used twice, and the attempt
 * counter loses increments to the same lost-update race. Single use and the
 * attempt budget are the two things standing between a six-digit code and an
 * attacker, so they cannot rest on a sequence the store is free to interleave.
 */
export interface CodeStore {
  get(key: string): Promise<unknown | null>
  put(key: string, value: unknown, ttlSeconds: number): Promise<void>
  forget(key: string): Promise<void>

  /**
   * Atomically read a value and remove it, returning null when absent.
   *
   * Exactly one caller may receive a given value. This is what makes a code
   * single-use under concurrency: the winner holds the only copy and either
   * accepts it or writes it back with one more attempt spent, while every other
   * concurrent caller sees nothing.
   *
   * Redis has GETDEL (6.2+) or EVAL; a SQL store can DELETE ... RETURNING.
   */
  take(key: string): Promise<unknown | null>

  /**
   * Atomically write a value only if the key is absent.
   *
   * @returns true when this call stored the value, false when one was already
   * present. The boolean is the point: it makes the write a reservation that
   * exactly one caller can win, which is how the cooldown and the webhook's
   * idempotency claim avoid check-then-write races.
   *
   * Redis has SET NX EX; Memcached has add().
   */
  add(key: string, value: unknown, ttlSeconds: number): Promise<boolean>
}

/**
 * Durable storage of the enrollment: which chat is an account's second factor,
 * and which generation of that enrollment is current.
 *
 * Two rules the implementation, not the caller, has to guarantee:
 *
 * 1. **Chat uniqueness, at the storage layer** - a unique index, not only an
 *    application check, because two concurrent links both pass a check and only
 *    one can pass an index.
 * 2. **Transitions are conditional.** Every change goes through transition(),
 *    which compares the stored generation and writes in one operation.
 *    Read-then-write cannot express this: a recovery landing between a caller's
 *    validation and its write would be silently overwritten, which is exactly
 *    how a replacement token outlived the enrollment it proved.
 */
export interface IdentityStore {
  /**
   * The enrollment for an account, or null when it has no row. May be unlinked;
   * the generation must be returned even when no chat is linked.
   */
  findByUserId(userId: string): Promise<Identity | null>

  /** Must never match an account whose chat id is null. */
  findByChatId(chatId: string): Promise<Identity | null>

  /**
   * Compare-and-set the enrollment.
   *
   * @param chatId   the chat to bind, or null to unlink
   * @param expected the generation the caller believes is current; null means
   *                 "none recorded yet"; ANY_GENERATION skips the check
   * @param next     the generation to store, always fresh - including on an
   *                 unlink, so authority over the old enrollment dies
   * @returns the new state, or null when the expectation did not hold, in which
   *          case the stored row must be left exactly as it was
   * @throws ChatAlreadyLinked when the chat belongs to another account
   */
  transition(
    userId: string,
    chatId: string | null,
    expected: string | null,
    next: string,
  ): Promise<Identity | null>
}

export interface InlineButton {
  text: string
  callback_data: string
}

/** The slice of the Telegram Bot API this library uses. */
export interface TelegramClient {
  sendMessage(chatId: string, text: string, inlineKeyboard?: InlineButton[][]): Promise<boolean>
  answerCallbackQuery(callbackQueryId: string, text?: string): Promise<boolean>
  getMe(): Promise<Record<string, unknown>>
  setWebhook(url: string, secretToken: string, allowedUpdates?: string[]): Promise<boolean>
  deleteWebhook(): Promise<boolean>
}

/**
 * A logging surface narrow enough that any logger satisfies it.
 *
 * Nothing passed to it contains a code, a link token or a raw update body.
 */
export interface Logger {
  info(message: string, context?: Record<string, unknown>): void
  warn(message: string, context?: Record<string, unknown>): void
  error(message: string, context?: Record<string, unknown>): void
}

export const nullLogger: Logger = {
  info: () => {},
  warn: () => {},
  error: () => {},
}

/** Injectable clock, so expiry and cooldown are testable without sleeping. */
export interface Clock {
  /** Current unix timestamp in seconds. */
  now(): number
}

export const systemClock: Clock = {
  now: () => Math.floor(Date.now() / 1000),
}

/** A clock that moves only when you move it. */
export class FrozenClock implements Clock {
  constructor(private current = 1_700_000_000) {}

  now(): number {
    return this.current
  }

  advance(seconds: number): this {
    this.current += seconds
    return this
  }

  setTo(timestamp: number): this {
    this.current = timestamp
    return this
  }
}

/**
 * Every piece of text the bot sends.
 *
 * Implement it to translate the bot or match your own tone. All strings are sent
 * with parse_mode HTML, so interpolated user-supplied text must be escaped - see
 * escapeHtml in messages.ts.
 */
export interface Messages {
  code(code: string, ttlSeconds: number): string
  linkInstructions(code: string, ttlSeconds: number, appName: string): string
  linkSucceeded(accountLabel: string, appName: string): string
  linkTokenInvalid(): string
  alreadyLinked(): string
  notLinked(appName: string): string
  cooldown(secondsRemaining: number): string
  /**
   * How to remove the factor, in answer to /unlink.
   *
   * The bot does not perform the removal: whoever holds the phone can already
   * read the codes, and letting them also remove the factor with no session and
   * no password turns a stolen phone into a permanently single-factor account.
   */
  unlinkInstructions(appName: string): string
  unlinked(appName: string): string
  welcome(isLinked: boolean, appName: string): string
  unknownCommand(): string
}
