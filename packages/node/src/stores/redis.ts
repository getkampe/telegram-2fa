import type { CodeStore } from '../contracts.js'

/**
 * The part of a Redis client this store uses.
 *
 * Satisfied by node-redis and by ioredis - their get and del signatures match,
 * and set with an expiry is normalised below. Declared structurally so the
 * package keeps zero runtime dependencies.
 */
export interface RedisLike {
  get(key: string): Promise<string | null>
  del(key: string | string[]): Promise<unknown>
  set(key: string, value: string, ...args: unknown[]): Promise<unknown>
}

/**
 * A production code store on Redis.
 *
 * Values are JSON. TTLs are set by Redis itself, which is why the library also
 * carries expiresAt inside the record: the two must agree, and the explicit
 * check is what makes expiry correct even on a store with coarse TTL
 * granularity or a clock that has drifted.
 */
export class RedisCodeStore implements CodeStore {
  constructor(
    private readonly redis: RedisLike,
    /**
     * node-redis takes { EX: seconds }; ioredis takes 'EX', seconds. Default
     * suits node-redis.
     */
    private readonly dialect: 'node-redis' | 'ioredis' = 'node-redis',
  ) {}

  async get(key: string): Promise<unknown | null> {
    const raw = await this.redis.get(key)

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
}
