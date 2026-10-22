import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ANY_GENERATION, FrozenClock } from '../src/contracts.js'
import { ErrorCode } from '../src/errors.js'
import { MemoryCodeStore, MemoryIdentityStore } from '../src/stores/memory.js'
import { DefaultMessages } from '../src/telegram/messages.js'
import {
  PURPOSE_REPLACE,
  PURPOSE_UNLINK,
  TelegramTwoFactor,
} from '../src/telegram-two-factor.js'
import { FakeTelegramClient, makeConfig, wrongCode } from './helpers.js'
import { InterleavingCodeStore } from './interleaving-store.js'
import { InterleavingIdentityStore } from './interleaving-identity-store.js'

/**
 * SPEC.md sections 2 and 5.1: the interleavings between an enrollment change
 * and whatever is holding authority over the enrollment it replaces.
 *
 * Every case fires a second operation from inside the first one's window
 * through a deterministic hook, never a sleep. Each protection is also checked
 * by removing it and confirming the matching case fails.
 */
describe('enrollment transitions under concurrency', () => {
  function raceHarness() {
    const clock = new FrozenClock()
    const store = new MemoryCodeStore(clock)
    const inner = new MemoryIdentityStore(clock)
    const identities = new InterleavingIdentityStore(inner)
    const telegram = new FakeTelegramClient()
    const config = makeConfig()

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
      store,
      identities,
      inner,
      telegram,
      config,
      tfa,
      lastCode: () => /<code>([^<]+)<\/code>/.exec(telegram.lastMessage())?.[1] ?? '',
      seed: (userId = 'user-1', chatId = '555000111') =>
        inner.seed(userId, chatId, 'gen-initial'),
    }
  }

  /**
   * The gap the conditional transition exists to close: validation of a
   * replacement token succeeds, a recovery lands, and the binding write then
   * applies to an enrollment the token never proved.
   */
  it('rejects a stale replacement when recovery lands before the write', async () => {
    const h = raceHarness()
    await h.seed()
    await h.tfa.push('user-1', PURPOSE_REPLACE)

    const request = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in request)

    h.identities.interleaveOnTransition(async () => {
      await h.tfa.unlinkAfterExternalProof('user-1', 'support recovered the account')
      const fresh = await h.tfa.startDeepLink('user-1')
      await h.tfa.completeDeepLink(fresh.token, '888000333')
    })

    const result = await h.tfa.completeDeepLink(request.token, '999000444')

    assert.equal(result.ok, false, 'a token proved against a superseded enrollment must fail')
    assert.equal(result.error, ErrorCode.InvalidToken)
    assert.equal(
      (await h.tfa.identity('user-1'))?.chatId,
      '888000333',
      'the recovered enrollment must survive the stale write',
    )
  })

  /**
   * The verification window: the record has been taken, a recovery revokes it,
   * and the failed-attempt path then writes it back.
   */
  it('cannot resurrect a code when recovery lands mid-verification', async () => {
    const h = raceHarness()
    await h.seed()
    await h.tfa.push('user-1')
    const code = h.lastCode()

    const racingStore = new InterleavingCodeStore(h.store)
    const tfa = new TelegramTwoFactor({
      config: h.config,
      store: racingStore,
      identities: h.identities,
      telegram: h.telegram,
      messages: new DefaultMessages(),
      clock: h.clock,
    })

    racingStore.interleaveOnTake(h.config.key('code', 'user-1'), async () => {
      await h.tfa.unlinkAfterExternalProof('user-1', 'support recovered the account')
      const fresh = await h.tfa.startDeepLink('user-1')
      await h.tfa.completeDeepLink(fresh.token, '888000333')
    })

    // A wrong guess, so the failed-attempt path runs and may write the record
    // back after the revocation.
    await tfa.verify('user-1', wrongCode(code))

    assert.equal(
      (await tfa.verify('user-1', code)).ok,
      false,
      'a code from a superseded enrollment must never be accepted',
    )
  })

  /**
   * The window between the code being accepted and the token being written.
   *
   * An earlier version re-read the identity after verifying and put *that*
   * generation into the token, meaning to fail early if anything had changed.
   * It did the opposite: a recovery landing in that window had its own fresh
   * generation, so the token was minted against the recovered enrollment — one
   * the user had never proved — and went on to replace the recovered chat.
   *
   * The generation written is now the one captured before verification, and a
   * change during verification is refused outright.
   */
  it('refuses authorisation when recovery lands between the code and the token', async () => {
    const h = raceHarness()
    await h.seed('victim')
    await h.tfa.push('victim', PURPOSE_REPLACE)
    const code = h.lastCode()

    // Fire the recovery on the identity read that happens after verify().
    let reads = 0
    const realFind = h.identities.findByUserId.bind(h.identities)
    h.identities.findByUserId = async (userId: string) => {
      reads++

      if (reads === 3) {
        await h.tfa.unlinkAfterExternalProof('victim', 'support recovery')
        const fresh = await h.tfa.startDeepLink('victim')
        await h.tfa.completeDeepLink(fresh.token, '888000333')
      }

      return realFind(userId)
    }

    const request = await h.tfa.startChatReplacement('victim', code)
    h.identities.findByUserId = realFind

    // Either it is refused here, or the token it produced is inert. Both are
    // acceptable; silently acquiring authority over the recovered enrollment
    // is not.
    if ('token' in request) {
      const result = await h.tfa.completeDeepLink(request.token, '999000444')

      assert.equal(result.ok, false, 'a token minted after recovery must not bind')
    }

    assert.equal(
      (await h.tfa.identity('victim'))?.chatId,
      '888000333',
      'the recovered enrollment must survive',
    )
  })

  /**
   * The guarantee stated in the design: preventing a stale record from being
   * written back is best-effort, but accepting one is impossible.
   *
   * So put the stale record back by hand - exactly what a lost race would do -
   * and require that it still cannot authorise anything. This isolates the
   * acceptance check; the previous case is satisfied by the restore guard
   * alone, which is the weaker of the two protections.
   */
  it('refuses a stale record even when one has been written back', async () => {
    const h = raceHarness()
    await h.seed()
    await h.tfa.push('user-1')
    const code = h.lastCode()

    const key = h.config.key('code', 'user-1')
    const record = await h.store.get(key)

    // Revoke the enrollment the record belongs to.
    await h.tfa.unlinkAfterExternalProof('user-1', 'support recovered the account')
    const fresh = await h.tfa.startDeepLink('user-1')
    await h.tfa.completeDeepLink(fresh.token, '888000333')

    // Resurrect it.
    await h.store.put(key, record, 300)

    assert.equal(
      (await h.tfa.verify('user-1', code)).ok,
      false,
      'a record from a superseded enrollment must be inert even if restored',
    )
  })

  /**
   * What the timestamp fingerprint could not express: unlinking and relinking
   * the same chat inside one second produced an identical chat_id|linked_at
   * pair, so authority minted before the unlink was still honoured after it.
   */
  it('invalidates old tokens across a same-second unlink and relink', async () => {
    const h = raceHarness()
    await h.seed()
    await h.tfa.push('user-1', PURPOSE_REPLACE)

    const stale = await h.tfa.startChatReplacement('user-1', h.lastCode())
    assert.ok('token' in stale)

    // No clock advance anywhere in this test: same second throughout.
    const before = h.clock.now()

    await h.tfa.unlinkAfterExternalProof('user-1', 'user asked')
    const fresh = await h.tfa.startDeepLink('user-1')
    await h.tfa.completeDeepLink(fresh.token, '555000111')

    assert.equal(h.clock.now(), before, 'the whole sequence is one second')
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '555000111')

    const result = await h.tfa.completeDeepLink(stale.token, '999000444')

    assert.equal(result.ok, false)
    assert.equal((await h.tfa.identity('user-1'))?.chatId, '555000111')
  })

  it('does not let two concurrent ordinary links replace each other', async () => {
    const h = raceHarness()
    const first = await h.tfa.startDeepLink('user-1')
    const second = await h.tfa.startDeepLink('user-1')

    let inner: Awaited<ReturnType<typeof h.tfa.completeDeepLink>> | null = null

    h.identities.interleaveOnTransition(async () => {
      inner = await h.tfa.completeDeepLink(second.token, '777000222')
    })

    const outer = await h.tfa.completeDeepLink(first.token, '555000111')

    assert.notEqual(inner, null)
    assert.notEqual(outer.ok, inner!.ok, 'exactly one of two concurrent links may win')

    // And whichever won, the stored enrollment is one of the two, not a
    // mixture: a chat that lost must not be recorded.
    const chatId = (await h.tfa.identity('user-1'))?.chatId
    assert.ok(chatId === '555000111' || chatId === '777000222')
    assert.equal((await h.tfa.identityForChat(chatId!))?.chatId, chatId)
  })

  /**
   * A delivery failure handler that runs late must not throw away a code the
   * user is already holding.
   */
  it('does not let a late delivery failure discard a newer challenge', async () => {
    const h = raceHarness()
    await h.seed()

    // The first send fails, but only after the cooldown has lapsed and a second
    // challenge has been issued and delivered.
    h.telegram.failNextSend(async () => {
      h.clock.advance(121)
      await h.tfa.push('user-1', 'login')
    })

    const failed = await h.tfa.push('user-1', 'login')
    assert.equal(failed.ok, false)
    assert.equal(failed.error, ErrorCode.SendFailed)

    assert.equal(
      (await h.tfa.verify('user-1', h.lastCode(), 'login')).ok,
      true,
      'the cleanup for a failed send must only discard its own challenge',
    )
  })

  it('leaves the enrollment alone when an unlink transition loses', async () => {
    const h = raceHarness()
    await h.seed()
    await h.tfa.push('user-1', PURPOSE_UNLINK)
    const code = h.lastCode()

    // A recovery lands between the code being accepted and the unlink write.
    h.identities.interleaveOnTransition(async () => {
      await h.inner.transition('user-1', '777000222', ANY_GENERATION, 'gen-recovered')
    })

    await h.tfa.unlink('user-1', code)

    const identity = await h.tfa.identity('user-1')
    assert.notEqual(identity, null)
    assert.equal(identity!.chatId, '777000222')
    assert.equal(identity!.generation, 'gen-recovered')
  })

  it('keeps the generation after unlinking', async () => {
    const h = raceHarness()
    await h.seed()

    await h.tfa.unlinkAfterExternalProof('user-1', 'user asked')

    const identity = await h.tfa.identity('user-1')

    // The row remains, carrying a new generation and no chat. This is what lets
    // revocation outlive the binding: a token minted before the unlink
    // references a generation that no longer matches, even after a relink.
    assert.notEqual(identity, null)
    assert.equal(identity!.chatId, null)
    assert.equal(identity!.linkedAt, null)
    assert.notEqual(identity!.generation, null)
    assert.notEqual(identity!.generation, 'gen-initial')
  })
})
