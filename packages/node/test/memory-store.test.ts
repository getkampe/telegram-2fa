import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { FrozenClock } from '../src/contracts.js'
import { MemoryCodeStore, MemoryIdentityStore } from '../src/stores/memory.js'
import { DefaultMessages } from '../src/telegram/messages.js'
import { TelegramTwoFactor } from '../src/telegram-two-factor.js'
import { ErrorCode } from '../src/errors.js'
import { FakeTelegramClient, makeConfig, wrongCode } from './helpers.js'

/**
 * The shipped in-memory primitives, exercised concurrently and directly.
 *
 * These tests exist because the previous suite tested concurrency only through
 * a wrapper that opened the interleaving window by hand. That proved the core
 * handled a race *when one occurred*, and proved nothing about whether the
 * store it ships with actually prevented one. It did not: `take()` was
 *
 *     const value = await this.get(key)
 *     this.items.delete(key)
 *
 * and the `await` is a suspension point, so two concurrent verifications of one
 * code both received the record and both returned ok — under a comment claiming
 * there was no gap between the read and the delete.
 *
 * `Promise.all` of two real calls is the test that catches that. No wrapper, no
 * hook, no sleep: just two operations in flight at once, which is what an
 * application does.
 */
describe('MemoryCodeStore under concurrency', () => {
  it('gives a value to only one of two concurrent takes', async () => {
    const store = new MemoryCodeStore(new FrozenClock())
    await store.put('k', 'value', 60)

    const results = await Promise.all([store.take('k'), store.take('k')])

    assert.deepEqual(
      results.filter((r) => r !== null),
      ['value'],
      'exactly one caller may receive the value',
    )
  })

  it('lets only one of two concurrent adds reserve the key', async () => {
    const store = new MemoryCodeStore(new FrozenClock())

    const results = await Promise.all([store.add('k', 1, 60), store.add('k', 2, 60)])

    assert.deepEqual(results.filter(Boolean), [true], 'exactly one reservation may win')
    assert.equal(await store.get('k'), 1, 'and the loser must not overwrite the winner')
  })

  it('gives a value to only one of many concurrent takes', async () => {
    const store = new MemoryCodeStore(new FrozenClock())
    await store.put('k', 'value', 60)

    const results = await Promise.all(Array.from({ length: 16 }, () => store.take('k')))

    assert.equal(results.filter((r) => r !== null).length, 1)
  })
})

describe('MemoryIdentityStore under concurrency', () => {
  it('applies only one of two concurrent transitions', async () => {
    const store = new MemoryIdentityStore(new FrozenClock())

    const results = await Promise.all([
      store.transition('u', '111', null, 'gen-a'),
      store.transition('u', '222', null, 'gen-b'),
    ])

    assert.equal(
      results.filter((r) => r !== null).length,
      1,
      'both started from the same expectation, so only one may apply',
    )

    // And the stored row is the winner's, not a mixture.
    const stored = await store.findByUserId('u')
    assert.ok(stored !== null)
    assert.ok(stored.generation === 'gen-a' || stored.generation === 'gen-b')
    assert.equal(
      stored.chatId,
      stored.generation === 'gen-a' ? '111' : '222',
      'chat and generation must come from the same transition',
    )
  })

  it('refuses a transition whose expectation is stale', async () => {
    const store = new MemoryIdentityStore(new FrozenClock())
    await store.transition('u', '111', null, 'gen-a')

    assert.equal(await store.transition('u', '222', null, 'gen-b'), null)
    assert.equal(await store.transition('u', '222', 'gen-a', 'gen-b') !== null, true)
  })
})

/**
 * The same thing end to end, which is the property an application depends on.
 */
describe('the service under concurrency, on the shipped stores', () => {
  function harness() {
    const clock = new FrozenClock()
    const identities = new MemoryIdentityStore(clock)
    const telegram = new FakeTelegramClient()
    const config = makeConfig()
    const store = new MemoryCodeStore(clock)

    const tfa = new TelegramTwoFactor({
      config,
      store,
      identities,
      telegram,
      messages: new DefaultMessages(),
      clock,
    })

    return {
      clock,
      identities,
      telegram,
      tfa,
      store: () => store,
      key: (kind: string, id: string) => config.key(kind, id),
      lastCode: () => /<code>([^<]+)<\/code>/.exec(telegram.lastMessage())?.[1] ?? '',
    }
  }

  it('accepts exactly one of two concurrent correct verifications', async () => {
    const h = harness()
    await h.identities.seed('user-1', '555000111', 'gen-initial')
    await h.tfa.push('user-1')
    const code = h.lastCode()

    const results = await Promise.all([
      h.tfa.verify('user-1', code),
      h.tfa.verify('user-1', code),
    ])

    assert.equal(
      results.filter((r) => r.ok).length,
      1,
      'a single-use code must authorise exactly one action',
    )
  })

  it('accepts exactly one of many concurrent correct verifications', async () => {
    const h = harness()
    await h.identities.seed('user-1', '555000111', 'gen-initial')
    await h.tfa.push('user-1')
    const code = h.lastCode()

    const results = await Promise.all(
      Array.from({ length: 16 }, () => h.tfa.verify('user-1', code)),
    )

    assert.equal(results.filter((r) => r.ok).length, 1)
  })

  /**
   * "Concurrent failures preserve the attempt budget" means no increment is
   * lost — not that firing ten guesses at once spends ten attempts.
   *
   * With an atomic take only one caller holds the record, so only that caller's
   * guess is ever compared; the rest are told `expired` without being
   * evaluated. That is the right outcome and it costs the attacker nothing to
   * their advantage: a guess that is never evaluated cannot be a hit. What must
   * hold is that every *evaluated* guess is counted, because a lost increment
   * is how the budget gets beaten by parallelism.
   */
  it('counts every evaluated guess when wrong guesses arrive together', async () => {
    const h = harness()
    await h.identities.seed('user-1', '555000111', 'gen-initial')
    await h.tfa.push('user-1')
    const wrong = wrongCode(h.lastCode())

    const results = await Promise.all(
      Array.from({ length: 10 }, () => h.tfa.verify('user-1', wrong)),
    )

    const evaluated = results.filter((r) => r.error === ErrorCode.Invalid).length
    const record = (await h.store().get(h.key('code', 'user-1'))) as { attempts: number } | null

    assert.ok(evaluated >= 1, 'at least one guess must actually be checked')
    assert.ok(record !== null, 'wrong guesses must not destroy the code before the budget is spent')
    assert.equal(
      record.attempts,
      evaluated,
      'every evaluated guess must be counted — a lost increment is how the budget is beaten',
    )
  })

  it('still exhausts the budget when wrong guesses arrive in sequence', async () => {
    const h = harness()
    await h.identities.seed('user-1', '555000111', 'gen-initial')
    await h.tfa.push('user-1')
    const code = h.lastCode()
    const wrong = wrongCode(code)

    for (let i = 0; i < 5; i++) {
      await h.tfa.verify('user-1', wrong)
    }

    assert.equal(
      (await h.tfa.verify('user-1', code)).ok,
      false,
      'five wrong guesses must kill the code',
    )
  })

  it('sends one code for two concurrent challenges', async () => {
    const h = harness()
    await h.identities.seed('user-1', '555000111', 'gen-initial')

    const results = await Promise.all([h.tfa.push('user-1'), h.tfa.push('user-1')])

    assert.equal(results.filter((r) => r.ok).length, 1)
    assert.equal(h.telegram.sent.length, 1)
  })

  it('binds one chat when two concurrent links resolve', async () => {
    const h = harness()
    const first = await h.tfa.startDeepLink('user-1')
    const second = await h.tfa.startDeepLink('user-1')

    const results = await Promise.all([
      h.tfa.completeDeepLink(first.token, '555000111'),
      h.tfa.completeDeepLink(second.token, '777000222'),
    ])

    assert.equal(results.filter((r) => r.ok).length, 1)

    const identity = await h.tfa.identity('user-1')
    assert.ok(identity !== null)
    assert.ok(identity.chatId === '555000111' || identity.chatId === '777000222')
  })

  it('resolves a single link token once when presented twice at the same moment', async () => {
    const h = harness()
    const request = await h.tfa.startDeepLink('user-1')

    const results = await Promise.all([
      h.tfa.completeDeepLink(request.token, '555000111'),
      h.tfa.completeDeepLink(request.token, '777000222'),
    ])

    assert.equal(results.filter((r) => r.ok).length, 1)
  })
})
