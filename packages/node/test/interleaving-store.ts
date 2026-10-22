import type { CodeStore } from '../src/contracts.js'

/**
 * A store that runs a second request in the middle of the first one's
 * read-modify-write, which is where a race lives.
 *
 * Node's event loop will not interleave two of these on its own without an
 * await landing in exactly the wrong place, and the bug does not depend on that
 * luck: it is that the sequence has an interleaving point at all. This wrapper
 * opens the point deliberately - the hook fires while the first caller is
 * between reading a record and writing its decision back - so a non-atomic
 * implementation shows the same double-success it would show under two real
 * requests against Redis.
 */
export class InterleavingCodeStore implements CodeStore {
  private hook: (() => Promise<void>) | null = null
  private hookPrefix = ''
  private fired = false

  constructor(private readonly inner: CodeStore) {}

  /**
   * Run the hook once, inside the next take() of a key starting with the
   * prefix, after the value has been removed and before the caller receives it.
   *
   * A prefix rather than an exact key, so a test can target the link record -
   * whose key is a hash of a token the library never exposes - without
   * reimplementing the derivation and coupling itself to it.
   */
  interleaveOnTake(keyPrefix: string, hook: () => Promise<void>): void {
    this.hookPrefix = keyPrefix
    this.hook = hook
    this.fired = false
  }

  /**
   * Run the hook once, inside the next add() of a matching key, before it is
   * attempted - the window a check-then-write cooldown would lose.
   */
  interleaveOnAdd(keyPrefix: string, hook: () => Promise<void>): void {
    this.interleaveOnTake(keyPrefix, hook)
  }

  async get(key: string): Promise<unknown | null> {
    return this.inner.get(key)
  }

  async put(key: string, value: unknown, ttlSeconds: number): Promise<void> {
    return this.inner.put(key, value, ttlSeconds)
  }

  async forget(key: string): Promise<void> {
    return this.inner.forget(key)
  }

  async take(key: string): Promise<unknown | null> {
    const value = await this.inner.take(key)

    await this.maybeFire(key)

    return value
  }

  async add(key: string, value: unknown, ttlSeconds: number): Promise<boolean> {
    await this.maybeFire(key)

    return this.inner.add(key, value, ttlSeconds)
  }

  private async maybeFire(key: string): Promise<void> {
    if (this.fired || this.hook === null || !key.startsWith(this.hookPrefix)) {
      return
    }

    this.fired = true
    await this.hook()
  }
}
