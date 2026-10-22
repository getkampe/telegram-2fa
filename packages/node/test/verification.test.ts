import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ErrorCode } from '../src/errors.js'
import { harness, wrongCode } from './helpers.js'

/** SPEC.md section 5. */
describe('verification', () => {
  it('accepts the right code', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')

    assert.equal((await h.tfa.verify('user-1', h.lastCode())).ok, true)
  })

  it('rejects a wrong code and spends an attempt', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')

    const result = await h.tfa.verify('user-1', wrongCode(h.lastCode()))

    assert.equal(result.error, ErrorCode.Invalid)
    assert.equal(result.attemptsRemaining, 4)
  })

  it('accepts a code only once', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')
    const code = h.lastCode()

    assert.equal((await h.tfa.verify('user-1', code)).ok, true)

    const replay = await h.tfa.verify('user-1', code)

    assert.equal(replay.ok, false)
    assert.equal(replay.error, ErrorCode.Expired)
  })

  it('kills the code when the attempt budget runs out', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')
    const code = h.lastCode()
    const wrong = wrongCode(code)

    for (let i = 0; i < 4; i++) {
      assert.equal((await h.tfa.verify('user-1', wrong)).error, ErrorCode.Invalid)
    }

    assert.equal((await h.tfa.verify('user-1', wrong)).error, ErrorCode.TooManyAttempts)

    // The real code is dead too, which is the point: the budget belongs to the
    // code, not to the attacker.
    assert.equal((await h.tfa.verify('user-1', code)).ok, false)
  })

  it('rejects an expired code', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')
    const code = h.lastCode()

    h.clock.advance(301)

    assert.equal((await h.tfa.verify('user-1', code)).error, ErrorCode.Expired)
  })

  /**
   * Re-storing the record on a failed attempt must not extend its life, or an
   * attacker can keep a code alive indefinitely by guessing wrong and the time
   * limit stops existing.
   */
  it('does not extend a code when a guess is wrong', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')
    const code = h.lastCode()

    h.clock.advance(200)
    await h.tfa.verify('user-1', wrongCode(code))

    h.clock.advance(101) // 301s since issue
    assert.equal((await h.tfa.verify('user-1', code)).error, ErrorCode.Expired)
  })

  it('reports expired when no code is in flight', async () => {
    const h = harness()
    await h.link()

    assert.equal((await h.tfa.verify('user-1', '123456')).error, ErrorCode.Expired)
  })

  it('tolerates whitespace around a pasted code', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')

    assert.equal((await h.tfa.verify('user-1', ` ${h.lastCode()}\n`)).ok, true)
  })

  it('does not let a code issued for one purpose satisfy another', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', 'login')
    const code = h.lastCode()

    assert.equal((await h.tfa.verify('user-1', code, 'withdrawal')).ok, false)
    assert.equal((await h.tfa.verify('user-1', code, 'login')).ok, true)
  })

  it('treats a user id as an opaque string', async () => {
    const h = harness()
    const uuid = '9b7c2f0e-4d5a-4c21-8f3b-1a2b3c4d5e6f'
    await h.identities.seed(uuid, '555000111', `gen-${uuid}`)

    assert.equal((await h.tfa.push(uuid)).ok, true)
    assert.equal((await h.tfa.verify(uuid, h.lastCode())).ok, true)
  })

  it('rejects a numerically equal but textually different code', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')
    const code = h.lastCode()

    for (const variant of [`${code}.0`, `0${code}`, ` 0x${code}`]) {
      assert.equal(
        (await h.tfa.verify('user-1', variant)).ok,
        false,
        `${variant} must not verify against ${code}`,
      )
    }
  })
})
