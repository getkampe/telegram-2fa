import type { CodeStore } from '../contracts.js'
import { ConfigurationError } from '../errors.js'

/**
 * The part of a Redis client this store uses.
 *
 * Declared structurally so the package keeps zero runtime dependencies, and
 * satisfied by both node-redis and ioredis. The optional members are the atomic
 * primitives: the two clients spell them differently, and one of them must be
 * present - see the constructor.
 */
export interface RedisLike {
  get(key: string): Promise<string | null>
  del(key: string | string[]): Promise<unknown>
  set(key: string, value: string, ...args: unknown[]): Promise<unknown>
  /** ioredis */
  getdel?(key: string): Promise<string | null>
  /** node-redis */
  getDel?(key: string): Promise<string | null>
  /** Either client, for servers older than Redis 6.2 which lack GETDEL. */
  eval?(script: string, ...args: unknown[]): Promise<unknown>
}

const TAKE_SCRIPT = `local v = redis.call('GET', KEYS[1])
if v then redis.call('DEL', KEYS[1]) end
return v`

/**
 * A production code store on Redis.
 *
 * Values are JSON, in the key layout and the field names of SPEC.md section 9,
 * so the PHP implementation reads and writes the same records.
 *
 * TTLs are set by Redis itself, which is why each record also carries its own
 * expires_at: the two must agree, and the explicit check is what keeps expiry
 * correct on a replica whose clock has drifted or a store with coarse TTL
 * granularity.
 */
export class RedisCodeStore implements CodeStore {
  private readonly takeImpl: (key: string) => Promise<string | null>

  constructor(
    private readonly redis: RedisLike,
    /**
     * node-redis takes { EX: seconds, NX: true }; ioredis takes
     * 'EX', seconds, 'NX'. Default suits node-redis.
     */
    private readonly dialect: 'node-redis' | 'ioredis' = 'node-redis',
  ) {
    // Resolved once, at construction, so a deployment missing an atomic
    // get-and-delete fails here rather than silently verifying one code twice
    // under load. See the CodeStore contract for why that is not negotiable.
    if (typeof redis.getdel === 'function') {
      this.takeImpl = (key) => redis.getdel!(key)
    } else if (typeof redis.getDel === 'function') {
      this.takeImpl = (key) => redis.getDel!(key)
    } else if (typeof redis.eval === 'function') {
      this.takeImpl = async (key) => {
        const result =
          dialect === 'ioredis'
            ? await redis.eval!(TAKE_SCRIPT, 1, key)
            : await redis.eval!(TAKE_SCRIPT, { keys: [key], arguments: [] })

        return typeof result === 'string' ? result : null
      }
    } else {
      throw new ConfigurationError(
        'This Redis client exposes neither GETDEL (getdel/getDel) nor EVAL, so it cannot ' +
          'remove a key and return its value in one operation. Without that, two ' +
          'simultaneous verifications of the same code can both succeed. Upgrade the ' +
          'client, or implement CodeStore against a primitive that is atomic.',
      )
    }
  }

  async get(key: string): Promise<unknown | null> {
    return this.decode(await this.redis.get(key))
  }

  async put(key: string, value: unknown, ttlSeconds: number): Promise<void> {
    const payload = JSON.stringify(value)

    if (this.dialect === 'ioredis') {
      await this.redis.set(key, payload, 'EX', ttlSeconds)
      return
    }

    await this.redis.set(key, payload, { EX: ttlSeconds })
  }

  async forget(key: string): Promise<void> {
    await this.redis.del(key)
  }

  async take(key: string): Promise<unknown | null> {
    return this.decode(await this.takeImpl(key))
  }

  async add(key: string, value: unknown, ttlSeconds: number): Promise<boolean> {
    const payload = JSON.stringify(value)

    // SET NX returns null (node-redis) or null/'OK' (ioredis) when the key
    // already exists, which is exactly the reservation semantics we need.
    const result =
      this.dialect === 'ioredis'
        ? await this.redis.set(key, payload, 'EX', ttlSeconds, 'NX')
        : await this.redis.set(key, payload, { EX: ttlSeconds, NX: true })

    return result !== null && result !== undefined
  }

  private decode(raw: string | null): unknown | null {
    if (raw === null) {
      return null
    }

    try {
      return JSON.parse(raw)
    } catch {
      // A value that is not JSON was not written by this library. Treating it
      // as absent is safer than throwing inside a verification path.
      return null
    }
  }
}
