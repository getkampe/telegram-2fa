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
 *
 * **Why every method body here is await-free.** These methods are `async`
 * because the contract is, but an `await` inside one would make it a
 * *suspension point*: the body stops, control returns to the event loop, and a
 * second caller can run its own read before the first has written anything.
 * An earlier version of this class did exactly that — `take()` was
 *
 *     const value = await this.get(key)
 *     this.items.delete(key)
 *
 * and two concurrent verifications of one code both received the record and
 * both succeeded, because the `await` on `get()` yielded between the read and
 * the delete. The comment above it claimed there was no such gap. There was.
 *
 * So each body below reads, decides and writes synchronously, and only the
 * implicit promise return happens afterwards. That is what makes `take` and
 * `add` the atomic primitives the contract asks for.
 */
export class MemoryCodeStore implements CodeStore {
  private items = new Map<string, { value: unknown; expiresAt: number }>()

  private readonly clock: Clock

  constructor(clock: Clock = systemClock) {
    this.clock = clock
  }

  async get(key: string): Promise<unknown | null> {
    return this.readSync(key)
  }

  async put(key: string, value: unknown, ttlSeconds: number): Promise<void> {
    this.items.set(key, { value, expiresAt: this.clock.now() + ttlSeconds })
  }

  async forget(key: string): Promise<void> {
    this.items.delete(key)
  }

  async take(key: string): Promise<unknown | null> {
    // Read and delete with nothing awaited in between, so a second caller
    // cannot observe the value this one is removing.
    const value = this.readSync(key)
    this.items.delete(key)

    return value
  }

  async add(key: string, value: unknown, ttlSeconds: number): Promise<boolean> {
    if (this.readSync(key) !== null) {
      return false
    }

    this.items.set(key, { value, expiresAt: this.clock.now() + ttlSeconds })

    return true
  }

  /** Synchronous read, including expiry, so callers need not await it. */
  private readSync(key: string): unknown | null {
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
}

/**
 * An in-memory identity store, for tests and for sketching an integration
 * before wiring it to a database.
 *
 * It models both rules a real store must enforce: one chat belongs to one
 * account, and a transition only applies when the stored generation is the one
 * the caller expected. Rows survive unlinking, because the generation has to.
 *
 * `transition` is await-free for the same reason as the code store above: an
 * `await` between checking the generation and writing the new state is a
 * suspension point, and two concurrent transitions would both pass the check.
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
    return this.findByChatIdSync(chatId)
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
      const holder = this.findByChatIdSync(chatId)

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

  private findByChatIdSync(chatId: string): Identity | null {
    for (const identity of this.rows.values()) {
      if (identity.chatId !== null && identity.chatId === chatId) {
        return identity
      }
    }

    return null
  }
}
