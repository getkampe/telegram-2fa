import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ErrorCode } from '../src/errors.js'
import { PURPOSE_REPLACE, PURPOSE_UNLINK } from '../src/telegram-two-factor.js'
import { harness, wrongCode } from './helpers.js'

/** SPEC.md section 3.3: moving the factor to a different Telegram account. */
describe('chat replacement', () => {
  it('moves the factor when the current one is proved', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_REPLACE)

    const request = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in request)

    const result = await h.tfa.completeDeepLink(request.token, '777000222')

    assert.equal(result.ok, true)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '777000222')
    assert.equal(await h.tfa.identityForChat('555000111'), null)
  })

  it('refuses a replacement without proof', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_REPLACE)

    const result = await h.tfa.startChatReplacement('user-1', wrongCode(h.lastCode()))

    assert.ok(!('token' in result))
    assert.equal(result.ok, false)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '555000111')
  })

  /**
   * The mark that authorises rebinding lives on the stored token. If it were
   * taken from the resolving call instead, the proof step could be skipped by
   * presenting an ordinary link token.
   */
  it('does not let an ordinary token move a verified binding', async () => {
    const h = harness()
    await h.link()

    const ordinary = await h.tfa.startDeepLink('user-1')
    const result = await h.tfa.completeDeepLink(ordinary.token, '777000222')

    assert.equal(result.error, ErrorCode.AlreadyLinked)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '555000111')
  })

  it('requires an existing link', async () => {
    const h = harness()

    const result = await h.tfa.startChatReplacement('user-1', '123456')

    assert.ok(!('token' in result))
    assert.equal(result.error, ErrorCode.NotLinked)
  })

  it('tells the old chat it is no longer the factor', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_REPLACE)

    const request = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in request)
    h.telegram.reset()

    await h.tfa.completeDeepLink(request.token, '777000222')

    // If the user did not request this, that message is how they find out.
    assert.equal(h.telegram.sent[0]?.chatId, '555000111')
    assert.match(h.telegram.sent[0]!.text.toLowerCase(), /unlinked/)
  })

  it('keeps the replacement token single-use', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_REPLACE)

    const request = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in request)

    await h.tfa.completeDeepLink(request.token, '777000222')
    const replay = await h.tfa.completeDeepLink(request.token, '888000333')

    assert.equal(replay.ok, false)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '777000222')
  })

  /**
   * A refused replacement must not cost the user the factor they already had.
   *
   * Releasing the old binding before checking the destination made a failed
   * request strip the account of its second factor as a side effect - the
   * account was left with no Telegram at all, and depending on policy either
   * locked out or protected by one factor. The old binding is now only released
   * by the same write that takes the new one.
   */
  it('leaves the original factor intact when refused', async () => {
    const h = harness()
    await h.link('user-1', '555000111')
    await h.link('user-2', '777000222')

    await h.tfa.push('user-1', PURPOSE_REPLACE)
    const request = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in request)

    const result = await h.tfa.completeDeepLink(request.token, '777000222')

    assert.equal(result.error, ErrorCode.AlreadyLinked)

    // The other account keeps its chat...
    assert.equal((await h.tfa.identityForChat('777000222'))?.userId, 'user-2')

    // ...and, the part that was broken, so does this one.
    assert.equal(await h.tfa.isLinked('user-1'), true)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '555000111')
  })

  it('does not announce a replacement that was refused', async () => {
    const h = harness()
    await h.link('user-1', '555000111')
    await h.link('user-2', '777000222')

    await h.tfa.push('user-1', PURPOSE_REPLACE)
    const request = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in request)
    h.telegram.reset()

    await h.tfa.completeDeepLink(request.token, '777000222')

    // Telling the user their factor was removed when it was not is its own
    // small incident: they will go looking for an attacker.
    assert.equal(h.telegram.sent.length, 0)
  })

  /**
   * Authority over a factor must not survive the factor.
   *
   * A replacement token proves possession of one particular binding. Once that
   * binding is gone - recovered through support, unlinked, or already replaced -
   * the proof refers to nothing, and honouring the token would hand whoever
   * holds it whatever binding came next.
   */
  it('voids a replacement token after account recovery', async () => {
    const h = harness()
    await h.link('user-1', '555000111')
    await h.tfa.push('user-1', PURPOSE_REPLACE)

    const stale = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in stale)

    // The user loses their Telegram account and support recovers them.
    await h.tfa.unlinkAfterExternalProof('user-1', 'identity verified out of band')

    const fresh = await h.tfa.startDeepLink('user-1')
    await h.tfa.completeDeepLink(fresh.token, '888000333')

    const result = await h.tfa.completeDeepLink(stale.token, '999000444')

    assert.equal(result.ok, false)
    assert.equal(result.error, ErrorCode.InvalidToken)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '888000333')
  })

  it('voids a replacement token after a completed replacement', async () => {
    const h = harness()
    await h.link('user-1', '555000111')

    await h.tfa.push('user-1', PURPOSE_REPLACE)
    const first = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in first)

    h.clock.advance(121)
    await h.tfa.push('user-1', PURPOSE_REPLACE)
    const second = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in second)

    // The second token is used; the first must now be worthless rather than a
    // standing right to move the factor again.
    assert.equal((await h.tfa.completeDeepLink(second.token, '777000222')).ok, true)

    const result = await h.tfa.completeDeepLink(first.token, '888000333')

    assert.equal(result.ok, false)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '777000222')
  })

  it('voids a replacement token after unlinking', async () => {
    const h = harness()
    await h.link('user-1', '555000111')

    await h.tfa.push('user-1', PURPOSE_REPLACE)
    const stale = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in stale)

    await h.tfa.unlinkAfterExternalProof('user-1', 'user asked')

    assert.equal((await h.tfa.completeDeepLink(stale.token, '999000444')).ok, false)
    assert.equal(await h.tfa.isLinked('user-1'), false)
  })

  /**
   * A code already delivered to the old chat is proof held by whoever still has
   * that chat, so it cannot outlive the binding it was sent to.
   */
  it('invalidates a code already sent to the old chat', async () => {
    const h = harness()
    await h.link('user-1', '555000111')

    await h.tfa.push('user-1', PURPOSE_REPLACE)
    const request = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in request)

    h.clock.advance(121)
    await h.tfa.push('user-1', 'login')
    const inFlight = h.lastCode()

    assert.equal((await h.tfa.completeDeepLink(request.token, '777000222')).ok, true)

    assert.equal(
      (await h.tfa.verify('user-1', inFlight, 'login')).ok,
      false,
      'a code delivered to the replaced chat must not verify afterwards',
    )
  })

  it('clears the cooldown so the new chat can be challenged at once', async () => {
    const h = harness()
    await h.link('user-1', '555000111')

    await h.tfa.push('user-1', PURPOSE_REPLACE)
    const request = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in request)

    await h.tfa.completeDeepLink(request.token, '777000222')

    // Otherwise the user has just linked a new chat and must wait out a
    // cooldown earned by the old one before they can prove anything.
    const challenge = await h.tfa.push('user-1', 'login')

    assert.equal(challenge.ok, true)
    assert.equal(h.telegram.sent.at(-1)?.chatId, '777000222')
  })

  it('leaves the old chat linked until the new one is resolved', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_REPLACE)

    const request = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in request)

    // Authorising a replacement must not strand the account factorless if the
    // user never completes it.
    assert.equal(await h.tfa.isLinked('user-1'), true)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '555000111')

    h.clock.advance(601)
    assert.equal((await h.tfa.completeDeepLink(request.token, '777000222')).ok, false)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '555000111')
  })
})

describe('/unlink in the chat', () => {
  it('explains where to unlink rather than doing it', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1', PURPOSE_UNLINK)

    // Covered end to end in webhook.test.ts; asserted here because the factor
    // surviving is the security property, not the wording.
    assert.equal(await h.tfa.isLinked('user-1'), true)
  })
})
