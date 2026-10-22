import {
  ANY_GENERATION,
  type Clock,
  type CodeStore,
  type Identity,
  type IdentityStore,
  systemClock,
} from '../contracts.js'
import { ChatAlreadyLinked } from '../errors.js'

/**
 * An in-process code store, for tests and single-process scripts.
 *
 * Not for production behind more than one process: each worker would hold its
 * own copy, so a code issued by one request would be invisible to the next. Use
 * Redis, or a table with an expires_at column.
 */
export class MemoryCodeStore implements CodeStore {
  private items = new Map<string, { value: unknown; expiresAt: number }>()

  private readonly clock: Clock

  constructor(clock: Clock = systemClock) {
    this.clock = clock
  }

  async get(key: string): Promise<unknown | null> {
    const item = this.items.get(key)

    if (item === undefined) {
      return null
    }

    if (item.expiresAt <= this.clock.now()) {
      this.items.delete(key)
      return null
    }

    return item.value
  }

  async put(key: string, value: unknown, ttlSeconds: number): Promise<void> {
    this.items.set(key, { value, expiresAt: this.clock.now() + ttlSeconds })
  }

  async forget(key: string): Promise<void> {
    this.items.delete(key)
  }

  /**
   * Trivially atomic here: one event loop, one Map, and no await between the
   * read and the delete for anything else to run in.
   */
  async take(key: string): Promise<unknown | null> {
    const value = await this.get(key)
    this.items.delete(key)

    return value
  }

  async add(key: string, value: unknown, ttlSeconds: number): Promise<boolean> {
    if ((await this.get(key)) !== null) {
      return false
    }

    await this.put(key, value, ttlSeconds)

    return true
  }
}

/**
 * An in-memory identity store, for tests and for sketching an integration
 * before wiring it to a database.
 *
 * It models both rules a real store must enforce: one chat belongs to one
 * account, and a transition only applies when the stored generation is the one
 * the caller expected. Rows survive unlinking, because the generation has to.
 */
export class MemoryIdentityStore implements IdentityStore {
  private rows = new Map<string, Identity>()

  private readonly clock: Clock

  constructor(clock: Clock = systemClock) {
    this.clock = clock
  }

  async findByUserId(userId: string): Promise<Identity | null> {
    return this.rows.get(userId) ?? null
  }

  async findByChatId(chatId: string): Promise<Identity | null> {
    for (const identity of this.rows.values()) {
      if (identity.chatId !== null && identity.chatId === chatId) {
        return identity
      }
    }

    return null
  }

  async transition(
    userId: string,
    chatId: string | null,
    expected: string | null,
    next: string,
  ): Promise<Identity | null> {
    const current = this.rows.get(userId) ?? null

    if (expected !== ANY_GENERATION && (current?.generation ?? null) !== expected) {
      // The expectation failed, so the stored row is left exactly as it was.
      // Returning null rather than throwing lets the caller decide whether this
      // is a conflict or a stale token.
      return null
    }

    if (chatId !== null) {
      const holder = await this.findByChatId(chatId)

      if (holder !== null && holder.userId !== userId) {
        throw new ChatAlreadyLinked(
          'That Telegram chat is already the second factor for another account.',
        )
      }
    }

    const identity: Identity = {
      userId,
      chatId,
      linkedAt: chatId === null ? null : this.clock.now(),
      generation: next,
    }

    this.rows.set(userId, identity)

    return identity
  }

  /** Test helper: seed a verified enrollment without going through a flow. */
  async seed(userId: string, chatId: string, generation: string): Promise<Identity> {
    const identity: Identity = {
      userId,
      chatId,
      linkedAt: this.clock.now(),
      generation,
    }

    this.rows.set(userId, identity)

    return identity
  }
}
