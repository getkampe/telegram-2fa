import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ConfigurationError } from '../src/errors.js'
import { UpdateHandler, type TelegramUpdate } from '../src/webhook/update-handler.js'
import { WebhookVerifier } from '../src/webhook/verifier.js'
import { harness, makeConfig } from './helpers.js'

const secret = 's'.repeat(48)

/**
 * SPEC.md section 7. The check that matters most: without it the webhook
 * accepts a forged assertion that any chat id is asking for a code.
 */
describe('webhook verifier', () => {
  it('accepts the matching secret', () => {
    assert.equal(new WebhookVerifier(makeConfig()).accepts(secret), true)
  })

  it('rejects a wrong secret', () => {
    assert.equal(new WebhookVerifier(makeConfig()).accepts('x'.repeat(48)), false)
  })

  it('rejects a missing secret', () => {
    const verifier = new WebhookVerifier(makeConfig())

    assert.equal(verifier.accepts(null), false)
    assert.equal(verifier.accepts(undefined), false)
    assert.equal(verifier.accepts(''), false)
  })

  it('rejects a prefix or an extension of the secret', () => {
    const verifier = new WebhookVerifier(makeConfig())

    assert.equal(verifier.accepts('s'.repeat(47)), false)
    assert.equal(verifier.accepts('s'.repeat(49)), false)
  })

  it('accepts Telegram ranges when IP restriction is on', () => {
    const verifier = new WebhookVerifier(makeConfig({ restrictWebhookIps: true }))

    assert.equal(verifier.accepts(secret, '149.154.160.1'), true)
    assert.equal(verifier.accepts(secret, '149.154.175.254'), true)
    assert.equal(verifier.accepts(secret, '91.108.4.10'), true)
  })

  it('rejects everything else when IP restriction is on', () => {
    const verifier = new WebhookVerifier(makeConfig({ restrictWebhookIps: true }))

    assert.equal(verifier.accepts(secret, '8.8.8.8'), false)
    assert.equal(verifier.accepts(secret, '149.154.176.1'), false)
    assert.equal(verifier.accepts(secret, '127.0.0.1'), false)
    assert.equal(verifier.accepts(secret, null), false)
    assert.equal(verifier.accepts(secret, 'not-an-ip'), false)
  })

  it('leaves IP restriction off by default', () => {
    // Off by default because behind a proxy the peer address is the proxy, so
    // the check would be either useless or actively misleading.
    assert.equal(new WebhookVerifier(makeConfig()).accepts(secret, '8.8.8.8'), true)
  })
})

describe('config validation of numbers', () => {
  /**
   * Every range check is a comparison, and a comparison against NaN is false -
   * so NaN passes every bound below it. It arrives easily, from Number(undefined)
   * or Number('5 minutes') in an environment-variable path.
   */
  it('rejects NaN where a number is required', () => {
    assert.throws(() => makeConfig({ maxAttempts: Number.NaN }), ConfigurationError)
    assert.throws(() => makeConfig({ codeTtl: Number.NaN }), ConfigurationError)
    assert.throws(() => makeConfig({ cooldown: Number.NaN }), ConfigurationError)
    assert.throws(() => makeConfig({ linkTtl: Number.NaN }), ConfigurationError)
  })

  it('rejects Infinity', () => {
    assert.throws(() => makeConfig({ codeTtl: Number.POSITIVE_INFINITY }), ConfigurationError)
    assert.throws(() => makeConfig({ cooldown: Number.NEGATIVE_INFINITY }), ConfigurationError)
  })

  it('rejects a fractional value', () => {
    // It would reach Redis as an EX argument.
    assert.throws(() => makeConfig({ codeTtl: 300.5 }), ConfigurationError)
    assert.throws(() => makeConfig({ maxAttempts: 2.5 }), ConfigurationError)
  })

  it('still accepts the whole numbers in range', () => {
    const config = makeConfig({ codeTtl: 120, cooldown: 60, maxAttempts: 3 })

    assert.equal(config.codeTtl, 120)
    assert.equal(config.maxAttempts, 3)
  })
})

describe('config validation', () => {
  it('refuses a missing webhook secret', () => {
    assert.throws(() => makeConfig({ webhookSecret: '' }), ConfigurationError)
  })

  it('refuses a short webhook secret', () => {
    // Telegram itself accepts a single character, which would satisfy the API
    // and defeat the purpose.
    assert.throws(() => makeConfig({ webhookSecret: 'x' }), ConfigurationError)
  })

  it('refuses a malformed bot token', () => {
    assert.throws(() => makeConfig({ botToken: 'not-a-token' }), ConfigurationError)
  })

  it('refuses a bot username with an at sign', () => {
    assert.throws(() => makeConfig({ botUsername: '@kampe_test_bot' }), ConfigurationError)
  })

  it('refuses unlimited attempts', () => {
    assert.throws(() => makeConfig({ maxAttempts: 0 }), ConfigurationError)
  })

  it('refuses a code that outlives its purpose', () => {
    assert.throws(() => makeConfig({ codeTtl: 86_400 }), ConfigurationError)
  })

  it('refuses a short link code', () => {
    assert.throws(() => makeConfig({ linkCodeLength: 6 }), ConfigurationError)
  })
})

describe('update handler', () => {
  let counter = 1000

  function message(text: string, chatId = '555000111'): TelegramUpdate {
    return {
      update_id: counter++,
      message: { message_id: 1, text, chat: { id: chatId, type: 'private' } },
    }
  }

  function handlerFor(h: ReturnType<typeof harness>): UpdateHandler {
    return new UpdateHandler({
      tfa: h.tfa,
      config: h.config,
      store: h.store,
      telegram: h.telegram,
      messages: h.messages,
      clock: h.clock,
    })
  }

  it('links the account on /start with a deeplink payload', async () => {
    const h = harness()
    const handler = handlerFor(h)
    const request = await h.tfa.startDeepLink('user-1')

    await handler.handle(message(`/start ${request.token}`))

    assert.equal(await h.tfa.isLinked('user-1'), true)
    assert.match(h.telegram.lastMessage(), /second factor/)
  })

  it('sends the welcome on /start with no payload', async () => {
    const h = harness()
    await handlerFor(h).handle(message('/start'))

    assert.match(h.telegram.lastMessage(), /security bot/)
  })

  it('issues a code on /code for a linked chat', async () => {
    const h = harness()
    await h.link()

    await handlerFor(h).handle(message('/code'))

    assert.match(h.lastCode(), /^\d{6}$/)
  })

  it('tells an unlinked chat how to link', async () => {
    const h = harness()
    await handlerFor(h).handle(message('/code'))

    assert.match(h.telegram.lastMessage(), /not linked/)
  })

  it('explains the wait inside the cooldown', async () => {
    const h = harness()
    const handler = handlerFor(h)
    await h.link()

    await handler.handle(message('/code'))
    await handler.handle(message('/code'))

    assert.match(h.telegram.lastMessage(), /just sent/)
  })

  /**
   * Telegram retries an update it believes was not delivered. Without
   * deduplication a retried /code mints a second code and resets the cooldown.
   */
  it('drops a repeated update id', async () => {
    const h = harness()
    const handler = handlerFor(h)
    await h.link()
    const update = message('/code')

    assert.equal(await handler.handle(update), true)
    assert.equal(await handler.handle(update), false)
    assert.equal(h.telegram.sent.length, 1)
  })

  it('ignores group chats', async () => {
    const h = harness()
    await h.link('user-1', '-1001234567890')

    const update = message('/code', '-1001234567890')
    update.message!.chat!.type = 'supergroup'

    await handlerFor(h).handle(update)

    // Otherwise the bot hands out verification codes in front of every member.
    assert.equal(h.telegram.sent.length, 0)
  })

  it('does not treat free text as a code', async () => {
    const h = harness()
    await h.link()

    await handlerFor(h).handle(message('123456'))

    assert.match(h.telegram.lastMessage(), /do not know that command/)
  })

  it('understands a command addressed to the bot by name', async () => {
    const h = harness()
    await h.link()

    await handlerFor(h).handle(message('/code@kampe_test_bot'))

    assert.match(h.lastCode(), /^\d{6}$/)
  })

  it('answers /unlink with instructions, and does not unlink', async () => {
    const h = harness()
    await h.link()

    await handlerFor(h).handle(message('/unlink'))

    // The question deserves an answer, not the generic menu - but the bot must
    // not perform the removal: whoever holds the phone could then strip the
    // factor with no session and no password.
    assert.match(h.telegram.lastMessage(), /cannot be done from the chat/)
    assert.equal(await h.tfa.isLinked('user-1'), true)
  })

  it('tells an unlinked chat there is nothing to unlink', async () => {
    const h = harness()

    await handlerFor(h).handle(message('/unlink'))

    assert.match(h.telegram.lastMessage(), /not linked/)
  })

  it('replies to an unknown command', async () => {
    const h = harness()
    await handlerFor(h).handle(message('/nonsense'))

    assert.match(h.telegram.lastMessage(), /do not know that command/)
  })

  it('dispatches a registered application command', async () => {
    const h = harness()
    let seen: [string, string] | null = null

    const handler = handlerFor(h).on('balance', (chatId, argument) => {
      seen = [chatId, argument]
    })

    await handler.handle(message('/balance usd'))

    assert.deepEqual(seen, ['555000111', 'usd'])
  })

  it('acknowledges a callback query then handles it', async () => {
    const h = harness()
    await h.link()

    await handlerFor(h).handle({
      update_id: 991,
      callback_query: {
        id: 'cb-1',
        data: 'code',
        message: { chat: { id: '555000111', type: 'private' } },
      },
    })

    assert.deepEqual(h.telegram.answeredCallbacks, ['cb-1'])
    assert.match(h.lastCode(), /^\d{6}$/)
  })

  it('ignores an update with no message', async () => {
    const h = harness()

    assert.equal(await handlerFor(h).handle({ update_id: 1 }), false)
    assert.equal(h.telegram.sent.length, 0)
  })

  /**
   * An update marked done before its work succeeds is an update permanently
   * lost: Telegram's retry arrives, sees the marker, and drops it as a
   * duplicate. The claim is released on failure so the retry is processed.
   */
  it('releases its claim when handling throws, so a retry is processed', async () => {
    const h = harness()
    await h.link()

    const handler = handlerFor(h).on('boom', () => {
      throw new Error('downstream failure')
    })

    const update = message('/boom')

    await assert.rejects(() => handler.handle(update), /downstream failure/)

    // The retry must not be mistaken for a duplicate of the failed attempt.
    let retried = false
    const retryHandler = handlerFor(h).on('boom', () => {
      retried = true
    })

    await retryHandler.handle(update)

    assert.equal(retried, true, "Telegram's retry of a failed update must be processed")
  })

  it('still drops a duplicate of an update that succeeded', async () => {
    const h = harness()
    await h.link()
    const handler = handlerFor(h)
    const update = message('/code')

    assert.equal(await handler.handle(update), true)
    assert.equal(await handler.handle(update), false)
    assert.equal(h.telegram.sent.length, 1)
  })
})
