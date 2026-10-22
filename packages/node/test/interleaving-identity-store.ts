import type { Identity, IdentityStore } from '../src/contracts.js'
import type { MemoryIdentityStore } from '../src/stores/memory.js'

/**
 * An identity store that runs a second operation inside the first one's
 * transition, immediately before the compare-and-set is evaluated.
 *
 * That is the window the conditional transition exists to close: a caller has
 * validated some state, something else changes it, and the caller's write then
 * lands on state it never checked. Firing the hook here is deterministic - no
 * sleeps, no reliance on where an await happens to yield - and reproduces what
 * two overlapping requests would do against a shared database.
 */
export class InterleavingIdentityStore implements IdentityStore {
  private hook: (() => Promise<void>) | null = null
  private fired = false

  constructor(private readonly innerStore: MemoryIdentityStore) {}

  inner(): MemoryIdentityStore {
    return this.innerStore
  }

  /** Run the hook once, inside the next transition, before it is evaluated. */
  interleaveOnTransition(hook: () => Promise<void>): void {
    this.hook = hook
    this.fired = false
  }

  async findByUserId(userId: string): Promise<Identity | null> {
    return this.innerStore.findByUserId(userId)
  }

  async findByChatId(chatId: string): Promise<Identity | null> {
    return this.innerStore.findByChatId(chatId)
  }

  async transition(
    userId: string,
    chatId: string | null,
    expected: string | null,
    next: string,
  ): Promise<Identity | null> {
    if (!this.fired && this.hook !== null) {
      this.fired = true
      await this.hook()
    }

    return this.innerStore.transition(userId, chatId, expected, next)
  }
}
