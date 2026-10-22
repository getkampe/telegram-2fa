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

  it('cannot take a chat that belongs to someone else', async () => {
    const h = harness()
    await h.link('user-1', '555000111')
    await h.link('user-2', '777000222')

    await h.tfa.push('user-1', PURPOSE_REPLACE)
    const request = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in request)

    const result = await h.tfa.completeDeepLink(request.token, '777000222')

    assert.equal(result.error, ErrorCode.AlreadyLinked)
    assert.equal((await h.tfa.identityForChat('777000222'))?.userId, 'user-2')
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
