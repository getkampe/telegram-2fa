import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { FrozenClock } from '../src/contracts.js'
import { ErrorCode } from '../src/errors.js'
import { MemoryCodeStore, MemoryIdentityStore } from '../src/stores/memory.js'
import { DefaultMessages } from '../src/telegram/messages.js'
import { TelegramTwoFactor, type VerificationResult } from '../src/telegram-two-factor.js'
import { FakeTelegramClient, makeConfig, wrongCode } from './helpers.js'
import { InterleavingCodeStore } from './interleaving-store.js'

/**
 * SPEC.md section 5.1: the state transitions that must be atomic.
 *
 * Single use and the attempt budget are the two things standing between a
 * six-digit code and an attacker, and both are read-modify-write sequences. If
 * the store is allowed to interleave them, a code verifies twice and wrong
 * guesses stop being counted.
 */
describe('concurrency', () => {
  function racingHarness() {
    const clock = new FrozenClock()
    const racing = new InterleavingCodeStore(new MemoryCodeStore(clock))
    const identities = new MemoryIdentityStore(clock)
    const telegram = new FakeTelegramClient()
    const config = makeConfig()

    const tfa = new TelegramTwoFactor({
      config,
      store: racing,
      identities,
      telegram,
      messages: new DefaultMessages(),
      clock,
    })

    return {
      clock,
      racing,
      identities,
      telegram,
      config,
      tfa,
      lastCode: () => /<code>([^<]+)<\/code>/.exec(telegram.lastMessage())?.[1] ?? '',
    }
  }

  it('does not let one code verify twice concurrently', async () => {
    const h = racingHarness()
    await h.identities.link('user-1', '555000111')
    await h.tfa.push('user-1')
    const code = h.lastCode()

    let second: VerificationResult | null = null

    // Fire a competing verification from inside the first one's window.
    h.racing.interleaveOnTake(h.config.key('code', 'user-1'), async () => {
      second = await h.tfa.verify('user-1', code)
    })

    const first = await h.tfa.verify('user-1', code)

    assert.equal(first.ok, true)
    assert.notEqual(second, null)
    assert.equal(
      second!.ok,
      false,
      'a single-use code must not succeed twice under concurrency',
    )
    assert.equal(second!.error, ErrorCode.Expired)
  })

  it('does not lose a wrong guess to a concurrent one', async () => {
    const h = racingHarness()
    await h.identities.link('user-1', '555000111')
    await h.tfa.push('user-1')
    const wrong = wrongCode(h.lastCode())

    let inner: VerificationResult | null = null

    h.racing.interleaveOnTake(h.config.key('code', 'user-1'), async () => {
      inner = await h.tfa.verify('user-1', wrong)
    })

    const outer = await h.tfa.verify('user-1', wrong)

    assert.equal(outer.ok, false)
    assert.notEqual(inner, null)
    assert.equal(inner!.ok, false)

    // A lost update here would make the five-attempt limit unenforceable by
    // simply racing it.
    const record = (await h.racing.get(h.config.key('code', 'user-1'))) as {
      attempts: number
    } | null

    assert.notEqual(record, null)
    assert.equal(record!.attempts, 1, 'the inner attempt holds the record, the outer finds none')
  })

  it('sends one code for two concurrent challenges', async () => {
    const h = racingHarness()
    await h.identities.link('user-1', '555000111')

    let second: Awaited<ReturnType<typeof h.tfa.push>> | null = null

    // The window a check-then-write cooldown would lose: both callers look,
    // neither sees a cooldown, both send.
    h.racing.interleaveOnAdd(h.config.key('cooldown', 'user-1'), async () => {
      second = await h.tfa.push('user-1')
    })

    const first = await h.tfa.push('user-1')

    assert.notEqual(second, null)
    assert.notEqual(
      first.ok,
      second!.ok,
      'exactly one of two concurrent challenges may win the cooldown',
    )
    assert.equal(h.telegram.sent.length, 1)
  })

  it('binds exactly one chat per link token', async () => {
    const h = racingHarness()
    const request = await h.tfa.startDeepLink('user-1')

    let second: Awaited<ReturnType<typeof h.tfa.completeDeepLink>> | null = null

    h.racing.interleaveOnTake(`${h.config.keyPrefix}:link:`, async () => {
      second = await h.tfa.completeDeepLink(request.token, '999000111')
    })

    const first = await h.tfa.completeDeepLink(request.token, '555000111')

    assert.equal(first.ok, true)
    assert.notEqual(second, null)
    assert.equal(second!.ok, false, 'a link token must bind exactly one chat')
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '555000111')
  })
})
