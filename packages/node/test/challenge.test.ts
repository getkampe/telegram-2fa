import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ErrorCode } from '../src/errors.js'
import { harness } from './helpers.js'

/** SPEC.md sections 4, 5 and 6. */
describe('challenge', () => {
  it('sends a code to the linked chat', async () => {
    const h = harness()
    await h.link()

    const result = await h.tfa.push('user-1')

    assert.equal(result.ok, true)
    assert.equal(h.telegram.sent.length, 1)
    assert.equal(h.telegram.sent[0]?.chatId, '555000111')
    assert.match(h.lastCode(), /^\d{6}$/)
  })

  it('refuses an unlinked account', async () => {
    const h = harness()

    const result = await h.tfa.push('nobody')

    assert.equal(result.ok, false)
    assert.equal(result.error, ErrorCode.NotLinked)
    assert.equal(h.telegram.sent.length, 0)
  })

  it('does not treat an unverified link as a second factor', async () => {
    const h = harness()
    // A chat id present with no verification timestamp: a link that was started
    // and never finished.
    h.identities.findByUserId = async (userId) => ({
      userId,
      chatId: '999',
      linkedAt: null,
      generation: 'gen-partial',
    })

    const result = await h.tfa.push('user-1')

    assert.equal(result.error, ErrorCode.NotLinked)
  })

  it('never puts the code in the result', async () => {
    const h = harness()
    await h.link()

    const result = await h.tfa.push('user-1')

    // The result is routinely returned straight to an HTTP client, so assert on
    // its serialised form rather than on its properties.
    assert.ok(!JSON.stringify(result).includes(h.lastCode()))
  })

  it('refuses a second request inside the cooldown', async () => {
    const h = harness()
    await h.link()

    await h.tfa.push('user-1')
    const second = await h.tfa.push('user-1')

    assert.equal(second.error, ErrorCode.Cooldown)
    assert.equal(second.nextSendAt, h.clock.now() + 120)
    assert.equal(h.telegram.sent.length, 1)
  })

  it('allows a request after the cooldown', async () => {
    const h = harness()
    await h.link()

    await h.tfa.push('user-1')
    h.clock.advance(121)

    assert.equal((await h.tfa.push('user-1')).ok, true)
    assert.equal(h.telegram.sent.length, 2)
  })

  it('leaves no live code and no cooldown when delivery fails', async () => {
    const h = harness()
    await h.link()
    h.telegram.shouldFailSending = true

    const failed = await h.tfa.push('user-1')
    assert.equal(failed.error, ErrorCode.SendFailed)

    // A code the user never received must not occupy the slot, or the account
    // is stuck until the cooldown expires with no way to try again.
    h.telegram.shouldFailSending = false
    assert.equal((await h.tfa.push('user-1')).ok, true)
  })

  it('issues a code on demand for a known chat', async () => {
    const h = harness()
    await h.link()

    const result = await h.tfa.pull('555000111')

    assert.equal(result.ok, true)
    assert.match(h.lastCode(), /^\d{6}$/)
  })

  it('refuses an on-demand code for an unknown chat', async () => {
    const h = harness()

    assert.equal((await h.tfa.pull('404404404')).error, ErrorCode.NotLinked)
  })

  /**
   * The single-key rule of SPEC.md section 4. An implementation that writes one
   * key on push and reads another passes every pull-path test and silently
   * fails every real push.
   */
  it('verifies a pushed code and a pulled code through the same call', async () => {
    const h = harness()
    await h.link()

    await h.tfa.push('user-1')
    assert.equal((await h.tfa.verify('user-1', h.lastCode())).ok, true)

    h.clock.advance(121)

    await h.tfa.pull('555000111')
    assert.equal((await h.tfa.verify('user-1', h.lastCode())).ok, true)
  })

  it('stores codes hashed', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')

    const record = (await h.store.get(h.config.key('code', 'user-1'))) as Record<string, unknown>

    assert.ok(record)
    assert.equal(record.code, undefined)
    assert.notEqual(record.hash, h.lastCode())
    assert.equal(String(record.hash).length, 64)
  })
})
