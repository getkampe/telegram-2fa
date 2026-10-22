import {
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
}

/**
 * An in-memory identity store, for tests and for sketching an integration
 * before wiring it to a database.
 *
 * It models the rule a real store must enforce with a unique constraint: one
 * chat belongs to one user, and a second claim is refused rather than allowed
 * to overwrite the first.
 */
export class MemoryIdentityStore implements IdentityStore {
  private byUser = new Map<string, Identity>()

  private readonly clock: Clock

  constructor(clock: Clock = systemClock) {
    this.clock = clock
  }

  async findByUserId(userId: string): Promise<Identity | null> {
    return this.byUser.get(userId) ?? null
  }

  async findByChatId(chatId: string): Promise<Identity | null> {
    for (const identity of this.byUser.values()) {
      if (identity.chatId === chatId) {
        return identity
      }
    }

    return null
  }

  async link(userId: string, chatId: string): Promise<Identity> {
    const holder = await this.findByChatId(chatId)

    if (holder !== null && holder.userId !== userId) {
      throw new ChatAlreadyLinked(
        'That Telegram chat is already the second factor for another account.',
      )
    }

    const identity: Identity = { userId, chatId, linkedAt: this.clock.now() }
    this.byUser.set(userId, identity)

    return identity
  }

  async unlink(userId: string): Promise<void> {
    this.byUser.delete(userId)
  }
}
