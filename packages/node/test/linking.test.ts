import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { LINK_ALPHABET } from '../src/codes.js'
import { ErrorCode } from '../src/errors.js'
import { harness, wrongCode } from './helpers.js'

/** SPEC.md sections 2 and 3. */
describe('linking', () => {
  it('links through the deeplink flow', async () => {
    const h = harness()

    const request = await h.tfa.startDeepLink('user-1')
    assert.equal(request.url, `https://t.me/kampe_test_bot?start=${request.token}`)

    const result = await h.tfa.completeDeepLink(request.token, '555000111')

    assert.equal(result.ok, true)
    assert.equal(await h.tfa.isLinked('user-1'), true)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '555000111')
  })

  it('accepts a deeplink token only once', async () => {
    const h = harness()
    const request = await h.tfa.startDeepLink('user-1')
    await h.tfa.completeDeepLink(request.token, '555000111')

    // A second presentation from a different chat: the obvious attack if the
    // token survives, since the token travels through a chat message.
    const replay = await h.tfa.completeDeepLink(request.token, '999999999')

    assert.equal(replay.error, ErrorCode.InvalidToken)
  })

  it('refuses an expired deeplink token', async () => {
    const h = harness()
    const request = await h.tfa.startDeepLink('user-1')

    h.clock.advance(601)

    assert.equal(
      (await h.tfa.completeDeepLink(request.token, '555000111')).error,
      ErrorCode.InvalidToken,
    )
  })

  it('refuses an unknown deeplink token', async () => {
    const h = harness()

    assert.equal(
      (await h.tfa.completeDeepLink('not-a-real-token', '555000111')).error,
      ErrorCode.InvalidToken,
    )
  })

  it('does not store the link token in plaintext', async () => {
    const h = harness()
    const request = await h.tfa.startDeepLink('user-1')

    assert.equal(await h.store.get(h.config.key('link', request.token)), null)
  })

  it('links through the paste flow', async () => {
    const h = harness()
    const request = await h.tfa.startPasteLink('555000111')

    assert.equal((await h.tfa.completePasteLink('user-1', request.token)).ok, true)
    assert.equal(await h.tfa.isLinked('user-1'), true)
  })

  it('accepts a paste code in lower case', async () => {
    const h = harness()
    const request = await h.tfa.startPasteLink('555000111')

    assert.equal(
      (await h.tfa.completePasteLink('user-1', request.token.toLowerCase())).ok,
      true,
    )
  })

  it('issues paste codes long enough to resist enumeration', async () => {
    const h = harness()
    const request = await h.tfa.startPasteLink('555000111')

    // The paste flow's key is derived from the code, so every outstanding code
    // shares one namespace. Six digits would be guessable; eight base32
    // characters is 40 bits.
    assert.equal(request.token.length, 8)
    assert.match(request.token, new RegExp(`^[${LINK_ALPHABET}]{8}$`))
  })

  /**
   * One Telegram account as the factor for several accounts means one
   * compromised Telegram account compromises all of them.
   */
  it('refuses to make one chat the factor for a second account', async () => {
    const h = harness()
    const first = await h.tfa.startDeepLink('user-1')
    await h.tfa.completeDeepLink(first.token, '555000111')

    const second = await h.tfa.startDeepLink('user-2')
    const result = await h.tfa.completeDeepLink(second.token, '555000111')

    assert.equal(result.error, ErrorCode.AlreadyLinked)
    assert.equal(await h.tfa.isLinked('user-2'), false)
    assert.equal((await h.tfa.identityForChat('555000111'))?.userId, 'user-1')
  })

  it('refuses to move an account to a second chat', async () => {
    const h = harness()
    const first = await h.tfa.startDeepLink('user-1')
    await h.tfa.completeDeepLink(first.token, '555000111')

    const second = await h.tfa.startDeepLink('user-1')
    const result = await h.tfa.completeDeepLink(second.token, '777000222')

    assert.equal(result.error, ErrorCode.AlreadyLinked)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '555000111')
  })

  it('treats relinking the same chat as a success', async () => {
    const h = harness()
    const first = await h.tfa.startDeepLink('user-1')
    await h.tfa.completeDeepLink(first.token, '555000111')

    // A user who taps the same link twice, or whose first confirmation was
    // lost, should see success rather than a conflict.
    const second = await h.tfa.startDeepLink('user-1')

    assert.equal((await h.tfa.completeDeepLink(second.token, '555000111')).ok, true)
  })
})

describe('unlinking', () => {
  it('requires a valid code', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')

    const result = await h.tfa.unlink('user-1', wrongCode(h.lastCode()))

    assert.equal(result.ok, false)
    assert.equal(await h.tfa.isLinked('user-1'), true)
  })

  it('removes the factor when the code is right', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')

    assert.equal((await h.tfa.unlink('user-1', h.lastCode())).ok, true)
    assert.equal(await h.tfa.isLinked('user-1'), false)
  })

  it('notifies the chat', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')

    const code = h.lastCode()
    h.telegram.reset()

    await h.tfa.unlink('user-1', code)

    assert.equal(h.telegram.sent.length, 1)
    assert.match(h.telegram.lastMessage().toLowerCase(), /unlinked/)
  })

  it('clears any code in flight', async () => {
    const h = harness()
    await h.link()
    await h.tfa.push('user-1')
    await h.tfa.unlink('user-1', h.lastCode())

    assert.equal(await h.store.get(h.config.key('code', 'user-1')), null)
    assert.equal(await h.store.get(h.config.key('cooldown', 'user-1')), null)
  })

  it('allows removal after an external proof, for recovery', async () => {
    const h = harness()
    await h.link()

    assert.equal(await h.tfa.unlinkAfterExternalProof('user-1', 'authenticator verified'), true)
    assert.equal(await h.tfa.isLinked('user-1'), false)
  })
})
