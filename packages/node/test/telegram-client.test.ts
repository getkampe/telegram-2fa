import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { Logger } from '../src/contracts.js'
import { FetchTelegramClient } from '../src/telegram/fetch-client.js'

const BOT_TOKEN = '123456789:AAFakeTokenForTestsOnly_0123456789abc'

/** Captures everything written, so a test can assert on all of it. */
class CapturingLogger implements Logger {
  readonly entries: string[] = []

  info(message: string, context?: Record<string, unknown>): void {
    this.record('info', message, context)
  }

  warn(message: string, context?: Record<string, unknown>): void {
    this.record('warn', message, context)
  }

  error(message: string, context?: Record<string, unknown>): void {
    this.record('error', message, context)
  }

  everything(): string {
    return this.entries.join('\n')
  }

  private record(level: string, message: string, context?: Record<string, unknown>): void {
    this.entries.push(`${level} ${message} ${JSON.stringify(context ?? {})}`)
  }
}

const jsonResponse = (body: unknown, status = 200): typeof fetch =>
  (async () =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch

const throwing = (error: Error): typeof fetch =>
  (async () => {
    throw error
  }) as unknown as typeof fetch

describe('FetchTelegramClient', () => {
  it('reports success when Telegram accepts the message', async () => {
    const client = new FetchTelegramClient({
      botToken: BOT_TOKEN,
      fetchImpl: jsonResponse({ ok: true, result: { message_id: 1 } }),
    })

    assert.equal(await client.sendMessage('555000111', 'hello'), true)
  })

  it('reports failure when a 200 carries ok:false', async () => {
    const logger = new CapturingLogger()
    const client = new FetchTelegramClient({
      botToken: BOT_TOKEN,
      logger,
      fetchImpl: jsonResponse({
        ok: false,
        error_code: 403,
        description: 'Forbidden: bot was blocked by the user',
      }),
    })

    assert.equal(await client.sendMessage('555000111', 'hello'), false)
    assert.match(logger.everything(), /Forbidden/)
  })

  it('reports failure when a 200 is not JSON at all', async () => {
    const client = new FetchTelegramClient({
      botToken: BOT_TOKEN,
      fetchImpl: jsonResponse('<html>captive portal</html>'),
    })

    assert.equal(await client.sendMessage('555000111', 'hello'), false)
  })

  it('reports failure rather than throwing when the transport fails', async () => {
    const client = new FetchTelegramClient({
      botToken: BOT_TOKEN,
      fetchImpl: throwing(new TypeError('fetch failed')),
    })

    assert.equal(await client.sendMessage('555000111', 'hello'), false)
  })

  /**
   * The bot token is in the request URL, because that is the API Telegram
   * exposes.
   *
   * Global fetch keeps the URL out of its error message, but fetchImpl is a
   * documented extension point and node-fetch reports `request to <url>
   * failed, reason: ...` with the token in the middle of it. A token in a log
   * file is a bot anyone who reads that file can impersonate.
   */
  it('never logs the bot token, whatever shape the error arrives in', async () => {
    const shapes = [
      new TypeError('fetch failed'),
      // node-fetch's FetchError, which is what a proxy-routed fetchImpl looks
      // like in practice.
      new Error(
        `request to https://api.telegram.org/bot${BOT_TOKEN}/sendMessage failed, reason: ECONNREFUSED`,
      ),
      new Error(`unexpected wrapper around https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`),
    ]

    for (const shape of shapes) {
      const logger = new CapturingLogger()
      const client = new FetchTelegramClient({
        botToken: BOT_TOKEN,
        logger,
        fetchImpl: throwing(shape),
      })

      await client.sendMessage('555000111', 'hello')

      assert.ok(logger.entries.length > 0, 'the failure must be logged, or this proves nothing')
      assert.ok(
        !logger.everything().includes(BOT_TOKEN),
        `the bot token reached the log: ${logger.everything()}`,
      )
      assert.ok(
        !logger.everything().includes('123456789:'),
        `part of the bot token reached the log: ${logger.everything()}`,
      )
    }
  })

  /** The error travels to the caller, who will log it too. */
  it('never puts the bot token in an error handed to the caller', async () => {
    const client = new FetchTelegramClient({
      botToken: BOT_TOKEN,
      fetchImpl: throwing(
        new Error(
          `request to https://api.telegram.org/bot${BOT_TOKEN}/getMe failed, reason: ECONNREFUSED`,
        ),
      ),
    })

    await assert.rejects(
      () => client.getMe(),
      (error: Error) => {
        assert.ok(!error.message.includes(BOT_TOKEN), error.message)
        assert.match(error.message, /\[redacted\]/)

        return true
      },
    )
  })
})
