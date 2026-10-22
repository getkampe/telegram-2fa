import { type InlineButton, type Logger, type TelegramClient, nullLogger } from '../contracts.js'
import { TelegramRequestFailed } from '../errors.js'

export interface FetchTelegramClientOptions {
  botToken: string
  timeoutMs?: number
  logger?: Logger
  parseMode?: 'HTML' | 'MarkdownV2'
  /** Override for tests, or to route through a proxy. */
  fetchImpl?: typeof fetch
}

/**
 * The default client: global fetch against api.telegram.org, no dependencies.
 *
 * Requires Node 18 or newer for fetch and AbortSignal.timeout. Substitute your
 * own implementation of TelegramClient to route through a queue or an existing
 * bot library.
 */
export class FetchTelegramClient implements TelegramClient {
  private readonly botToken: string
  private readonly timeoutMs: number
  private readonly logger: Logger
  private readonly parseMode: string
  private readonly fetchImpl: typeof fetch

  constructor(options: FetchTelegramClientOptions) {
    this.botToken = options.botToken
    this.timeoutMs = options.timeoutMs ?? 10_000
    this.logger = options.logger ?? nullLogger
    this.parseMode = options.parseMode ?? 'HTML'
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch

    if (typeof this.fetchImpl !== 'function') {
      throw new TelegramRequestFailed(
        'No fetch implementation available. Use Node 18 or newer, or pass fetchImpl.',
      )
    }
  }

  async sendMessage(
    chatId: string,
    text: string,
    inlineKeyboard?: InlineButton[][],
  ): Promise<boolean> {
    const payload: Record<string, unknown> = {
      chat_id: chatId,
      text,
      parse_mode: this.parseMode,
      disable_web_page_preview: true,
    }

    if (inlineKeyboard !== undefined) {
      payload.reply_markup = { inline_keyboard: inlineKeyboard }
    }

    try {
      await this.call('sendMessage', payload)
      return true
    } catch (error) {
      // Delivery is fallible and the caller has a fallback, so this is reported
      // rather than thrown. The message body is never logged: for a challenge,
      // the body is the code.
      this.logger.error('telegram-2fa: sendMessage failed', {
        reason: error instanceof Error ? error.message : 'unknown',
      })

      return false
    }
  }

  async answerCallbackQuery(callbackQueryId: string, text?: string): Promise<boolean> {
    try {
      await this.call('answerCallbackQuery', {
        callback_query_id: callbackQueryId,
        ...(text === undefined ? {} : { text }),
      })

      return true
    } catch {
      return false
    }
  }

  async getMe(): Promise<Record<string, unknown>> {
    const result = await this.call('getMe', {})

    return typeof result === 'object' && result !== null
      ? (result as Record<string, unknown>)
      : {}
  }

  async setWebhook(url: string, secretToken: string, allowedUpdates?: string[]): Promise<boolean> {
    if (!url.startsWith('https://')) {
      throw new TelegramRequestFailed(
        'Telegram will only deliver webhooks to an https URL with a valid certificate.',
      )
    }

    await this.call('setWebhook', {
      url,
      secret_token: secretToken,
      allowed_updates: allowedUpdates ?? ['message', 'callback_query'],
      // Telegram queues updates while a webhook is unset or failing. On a first
      // deploy that queue can hold stale /code requests, so it is dropped
      // rather than replayed into a live 2FA flow.
      drop_pending_updates: true,
    })

    return true
  }

  async deleteWebhook(): Promise<boolean> {
    await this.call('deleteWebhook', { drop_pending_updates: true })

    return true
  }

  private async call(method: string, payload: Record<string, unknown>): Promise<unknown> {
    let response: Response

    try {
      response = await this.fetchImpl(
        `https://api.telegram.org/bot${this.botToken}/${method}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(this.timeoutMs),
        },
      )
    } catch (error) {
      throw new TelegramRequestFailed(
        `Telegram could not be reached: ${error instanceof Error ? error.message : 'unknown'}`,
      )
    }

    let body: { ok?: boolean; result?: unknown; description?: string }

    try {
      body = (await response.json()) as typeof body
    } catch {
      throw new TelegramRequestFailed(
        `Telegram returned a non-JSON response with status ${response.status}.`,
      )
    }

    if (body.ok !== true) {
      // description is Telegram's own error text and does not echo the message
      // body back, so it is safe to surface.
      throw new TelegramRequestFailed(
        `Telegram rejected ${method} with status ${response.status}: ` +
          `${body.description ?? 'no description'}`,
      )
    }

    return body.result ?? true
  }
}
