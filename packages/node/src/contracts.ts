/**
 * Everything the library needs from the outside world.
 *
 * All four are small on purpose: an integration is four adapters, each a handful
 * of lines, rather than a framework to adopt.
 */

/** A user-to-chat binding as the identity store holds it. */
export interface Identity {
  userId: string
  chatId: string
  /** Unix seconds when the link was proven, or null when it was not. */
  linkedAt: number | null
}

/**
 * Only a verified link counts as a second factor.
 *
 * A record carrying a chat id with no timestamp is a link that was started and
 * never completed. Treating it as linked would let anyone who can write a chat
 * id into the record satisfy a challenge.
 */
export function isVerified(identity: Identity | null | undefined): boolean {
  return identity?.linkedAt != null
}

/**
 * Short-lived key/value storage with a TTL.
 *
 * Redis, Memcached, a Postgres table with an expires_at column - anything with
 * expiry. It holds code hashes, never plaintext codes.
 */
export interface CodeStore {
  get(key: string): Promise<unknown | null>
  put(key: string, value: unknown, ttlSeconds: number): Promise<void>
  forget(key: string): Promise<void>
}

/**
 * Durable storage of the binding, usually three columns on your users table.
 *
 * See SPEC.md section 2: both directions must be unique, and the uniqueness of
 * chatId must be enforced by the database rather than only by application code.
 */
export interface IdentityStore {
  findByUserId(userId: string): Promise<Identity | null>
  findByChatId(chatId: string): Promise<Identity | null>
  /** Must throw ChatAlreadyLinked rather than reassign a taken chat. */
  link(userId: string, chatId: string): Promise<Identity>
  unlink(userId: string): Promise<void>
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
  unlinked(appName: string): string
  welcome(isLinked: boolean, appName: string): string
  unknownCommand(): string
}
