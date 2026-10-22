import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ErrorCode } from '../src/errors.js'
import {
  PURPOSE_LOGIN,
  PURPOSE_REPLACE,
  PURPOSE_UNLINK,
} from '../src/telegram-two-factor.js'
import { harness, wrongCode } from './helpers.js'

/**
 * SPEC.md sections 4.1, 4.2 and 5: a code authorises the step it was issued for
 * and no other, and the check cannot be skipped.
 */
describe('purpose binding', () => {
  it('accepts a pushed code for its own purpose', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', 'withdrawal')

    assert.equal((await h.tfa.verify('user-1', h.lastCode(), 'withdrawal')).ok, true)
  })

  it('rejects a pushed code for another purpose', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_LOGIN)

    assert.equal((await h.tfa.verify('user-1', h.lastCode(), 'withdrawal')).ok, false)
  })

  /**
   * The hole this test exists for: when the purpose argument was optional and
   * defaulted to "compare against nothing", a login code approved a withdrawal
   * at any call site that forgot to pass the purpose through - and that call
   * site is both invisible and the one that matters.
   */
  it('does not let a login code approve a privileged step by omission', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_LOGIN)

    assert.equal((await h.tfa.verify('user-1', h.lastCode(), 'withdrawal')).ok, false)

    // And the default is login, not a wildcard.
    h.clock.advance(121)
    await h.tfa.push('user-1', 'withdrawal')

    assert.equal(
      (await h.tfa.verify('user-1', h.lastCode())).ok,
      false,
      'omitting the purpose must mean login, never a wildcard',
    )
  })

  it('treats an on-demand code as general-purpose', async () => {
    const h = harness()
    await h.link()

    // A code the user fetched with /code cannot know what it is for.
    await h.tfa.pull('555000111')
    assert.equal((await h.tfa.verify('user-1', h.lastCode(), 'withdrawal')).ok, true)

    h.clock.advance(121)

    await h.tfa.pull('555000111')
    assert.equal((await h.tfa.verify('user-1', h.lastCode(), PURPOSE_LOGIN)).ok, true)
  })

  it('reports a purpose mismatch as invalid, not as its own error', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_LOGIN)

    // A distinct error would tell a caller that a live code exists for a
    // different step, which it has not proved it may know.
    const result = await h.tfa.verify('user-1', h.lastCode(), 'withdrawal')

    assert.equal(result.error, ErrorCode.Invalid)
  })

  it('spends an attempt on a purpose mismatch', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_LOGIN)
    const code = h.lastCode()

    // Otherwise the mismatch path is a free, unbudgeted oracle.
    assert.equal((await h.tfa.verify('user-1', code, 'withdrawal')).attemptsRemaining, 4)
    assert.equal((await h.tfa.verify('user-1', code, 'withdrawal')).attemptsRemaining, 3)
  })

  it('refuses to unlink with a code pushed for a login', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_LOGIN)

    assert.equal((await h.tfa.unlink('user-1', h.lastCode())).ok, false)
    assert.equal(await h.tfa.isLinked('user-1'), true)
  })

  it('unlinks with a code the user fetched', async () => {
    const h = harness()
    await h.link()
    await h.tfa.pull('555000111')

    assert.equal((await h.tfa.unlink('user-1', h.lastCode())).ok, true)
    assert.equal(await h.tfa.isLinked('user-1'), false)
  })

  it('unlinks with a code pushed for unlinking', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_UNLINK)

    assert.equal((await h.tfa.unlink('user-1', h.lastCode())).ok, true)
  })

  it('refuses a replacement authorised by a login code', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_LOGIN)

    const result = await h.tfa.startChatReplacement('user-1', h.lastCode())

    assert.ok(!('token' in result))
    assert.equal(result.ok, false)
  })

  it('still budgets attempts when the purpose is right but the code is wrong', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_REPLACE)
    const wrong = wrongCode(h.lastCode())

    const result = await h.tfa.verify('user-1', wrong, PURPOSE_REPLACE)

    assert.equal(result.error, ErrorCode.Invalid)
    assert.equal(result.attemptsRemaining, 4)
  })
})
