import { Config, type ConfigInput } from '../src/config.js'
import { FrozenClock, type InlineButton, type TelegramClient } from '../src/contracts.js'
import { MemoryCodeStore, MemoryIdentityStore } from '../src/stores/memory.js'
import { DefaultMessages } from '../src/telegram/messages.js'
import { TelegramTwoFactor } from '../src/telegram-two-factor.js'

export class FakeTelegramClient implements TelegramClient {
  sent: Array<{ chatId: string; text: string }> = []
  answeredCallbacks: string[] = []
  shouldFailSending = false

  private duringNextFailure: (() => Promise<void>) | null = null

  /**
   * Fail the next send, running `during` while it is "in flight".
   *
   * Models a send that blocks long enough for the world to move on - the
   * cooldown lapsing and another challenge being issued - before the failure is
   * reported and its cleanup runs.
   */
  failNextSend(during: () => Promise<void>): void {
    this.shouldFailSending = true
    this.duringNextFailure = during
  }

  async sendMessage(chatId: string, text: string, _keyboard?: InlineButton[][]): Promise<boolean> {
    if (this.shouldFailSending) {
      if (this.duringNextFailure !== null) {
        // One-shot: the hook models a single slow, failing send, and the sends
        // it triggers must succeed.
        const during = this.duringNextFailure
        this.duringNextFailure = null
        this.shouldFailSending = false
        await during()
      }

      return false
    }

    this.sent.push({ chatId, text })

    return true
  }

  async answerCallbackQuery(callbackQueryId: string): Promise<boolean> {
    this.answeredCallbacks.push(callbackQueryId)

    return true
  }

  async getMe(): Promise<Record<string, unknown>> {
    return { id: 1, username: 'kampe_test_bot', first_name: 'Kampe' }
  }

  async setWebhook(): Promise<boolean> {
    return true
  }

  async deleteWebhook(): Promise<boolean> {
    return true
  }

  lastMessage(): string {
    return this.sent.at(-1)?.text ?? ''
  }

  reset(): void {
    this.sent = []
    this.answeredCallbacks = []
  }
}

export function makeConfig(overrides: Partial<ConfigInput> = {}): Config {
  return new Config({
    botToken: '123456789:AAFakeTokenForTestsOnly_0123456789abc',
    webhookSecret: 's'.repeat(48),
    botUsername: 'kampe_test_bot',
    appName: 'Kampe',
    hashPepper: 'p'.repeat(48),
    ...overrides,
  })
}

export interface Harness {
  clock: FrozenClock
  store: MemoryCodeStore
  identities: MemoryIdentityStore
  telegram: FakeTelegramClient
  config: Config
  tfa: TelegramTwoFactor
  messages: DefaultMessages
  /** The code from the most recent outgoing message. */
  lastCode(): string
  link(userId?: string, chatId?: string): Promise<void>
}

/**
 * A fully wired instance on in-memory parts.
 */
export function harness(overrides: Partial<ConfigInput> = {}): Harness {
  const clock = new FrozenClock()
  const store = new MemoryCodeStore(clock)
  const identities = new MemoryIdentityStore(clock)
  const telegram = new FakeTelegramClient()
  const config = makeConfig(overrides)
  const messages = new DefaultMessages()

  const tfa = new TelegramTwoFactor({
    config,
    store,
    identities,
    telegram,
    messages,
    clock,
  })

  return {
    clock,
    store,
    identities,
    telegram,
    config,
    tfa,
    messages,
    // Tests have to recover the code from the outgoing message, because the
    // library deliberately never returns it.
    lastCode: () => /<code>([^<]+)<\/code>/.exec(telegram.lastMessage())?.[1] ?? '',
    link: async (userId = 'user-1', chatId = '555000111') => {
      await identities.seed(userId, chatId, `gen-${userId}`)
    },
  }
}

/** A code guaranteed to differ from the given one. */
export function wrongCode(code: string): string {
  return code === '000000' ? '111111' : '000000'
}
