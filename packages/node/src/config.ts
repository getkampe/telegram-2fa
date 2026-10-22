import { ConfigurationError } from './errors.js'

export interface ConfigInput {
  botToken: string
  webhookSecret: string
  botUsername?: string | null
  appName?: string
  codeLength?: number
  codeTtl?: number
  cooldown?: number
  maxAttempts?: number
  linkCodeLength?: number
  linkTtl?: number
  keyPrefix?: string
  hashAlgorithm?: string
  hashPepper?: string
  dedupeUpdates?: boolean
  updateDedupeTtl?: number
  restrictWebhookIps?: boolean
}

const defaults = {
  appName: 'Kampe',
  codeLength: 6,
  codeTtl: 300,
  cooldown: 120,
  maxAttempts: 5,
  linkCodeLength: 8,
  linkTtl: 600,
  keyPrefix: 'tg2fa',
  hashAlgorithm: 'sha256',
  hashPepper: '',
  dedupeUpdates: true,
  updateDedupeTtl: 3600,
  restrictWebhookIps: false,
}

/**
 * Validated configuration.
 *
 * Rejects anything that cannot be secure instead of accepting it and logging a
 * warning nobody reads. The clearest case is a missing webhook secret: without
 * one the webhook is an open endpoint that mints a code for any chat id a
 * stranger posts to it, and the application looks like it is working. Failing at
 * startup is the only version of that outcome anyone notices.
 */
export class Config {
  readonly botToken: string
  readonly webhookSecret: string
  readonly botUsername: string | null
  readonly appName: string
  readonly codeLength: number
  readonly codeTtl: number
  readonly cooldown: number
  readonly maxAttempts: number
  readonly linkCodeLength: number
  readonly linkTtl: number
  readonly keyPrefix: string
  readonly hashAlgorithm: string
  readonly hashPepper: string
  readonly dedupeUpdates: boolean
  readonly updateDedupeTtl: number
  readonly restrictWebhookIps: boolean

  constructor(input: ConfigInput) {
    const c = { ...defaults, ...input }

    this.botToken = c.botToken ?? ''
    this.webhookSecret = c.webhookSecret ?? ''
    this.botUsername = c.botUsername ?? null
    this.appName = c.appName
    this.codeLength = c.codeLength
    this.codeTtl = c.codeTtl
    this.cooldown = c.cooldown
    this.maxAttempts = c.maxAttempts
    this.linkCodeLength = c.linkCodeLength
    this.linkTtl = c.linkTtl
    this.keyPrefix = c.keyPrefix
    this.hashAlgorithm = c.hashAlgorithm
    this.hashPepper = c.hashPepper
    this.dedupeUpdates = c.dedupeUpdates
    this.updateDedupeTtl = c.updateDedupeTtl
    this.restrictWebhookIps = c.restrictWebhookIps

    this.validate()
  }

  private validate(): void {
    if (this.botToken.trim() === '') {
      throw new ConfigurationError(
        'A bot token is required. Create a bot with @BotFather and set TELEGRAM_BOT_TOKEN.',
      )
    }

    if (!/^\d+:[A-Za-z0-9_-]{30,}$/.test(this.botToken)) {
      throw new ConfigurationError(
        'The bot token is not in the format @BotFather issues (123456789:AA...). ' +
          'Check that the value was not truncated or quoted.',
      )
    }

    // Telegram accepts 1 to 256 characters. One character would satisfy
    // Telegram and defeat the purpose, so the floor of 32 is ours.
    if (!/^[A-Za-z0-9_-]{32,256}$/.test(this.webhookSecret)) {
      throw new ConfigurationError(
        'The webhook secret must be 32 to 256 characters of A-Z, a-z, 0-9, underscore or hyphen. ' +
          'Generate one with new CodeGenerator().webhookSecret() and set TELEGRAM_WEBHOOK_SECRET. ' +
          'This is what stops a stranger forging updates against your webhook; it is not optional.',
      )
    }

    if (this.botUsername !== null && !/^[A-Za-z0-9_]{5,32}$/.test(this.botUsername)) {
      throw new ConfigurationError(
        'The bot username must be 5 to 32 characters of A-Z, a-z, 0-9 or underscore, with no leading @.',
      )
    }

    if (this.codeLength < 6 || this.codeLength > 8) {
      throw new ConfigurationError('codeLength must be between 6 and 8.')
    }

    if (this.codeTtl < 30 || this.codeTtl > 600) {
      throw new ConfigurationError(
        'codeTtl must be between 30 and 600 seconds. A code that outlives the step it ' +
          'authorises is a code sitting in a chat history waiting to be reused.',
      )
    }

    if (this.cooldown < 30) {
      throw new ConfigurationError(
        'cooldown must be at least 30 seconds, or the bot becomes a way to spam someone ' +
          'via your bot token.',
      )
    }

    if (this.maxAttempts < 1 || this.maxAttempts > 10) {
      throw new ConfigurationError(
        'maxAttempts must be between 1 and 10. Unlimited attempts against a six-digit ' +
          'code is not two-factor authentication.',
      )
    }

    if (this.linkCodeLength < 8) {
      throw new ConfigurationError(
        'linkCodeLength must be at least 8. Paste-flow codes are stored under a key derived ' +
          'from the code, so they share one namespace across every user and a short code is ' +
          'enumerable.',
      )
    }

    if (this.linkTtl < 60 || this.linkTtl > 900) {
      throw new ConfigurationError('linkTtl must be between 60 and 900 seconds.')
    }

    if (this.keyPrefix === '' || this.keyPrefix.includes(':')) {
      throw new ConfigurationError('keyPrefix must be non-empty and must not contain a colon.')
    }
  }

  /**
   * Build from environment variables, for the common case.
   */
  static fromEnv(env: Record<string, string | undefined> = process.env): Config {
    const num = (value: string | undefined, fallback: number): number =>
      value === undefined || value === '' ? fallback : Number(value)

    return new Config({
      botToken: env.TELEGRAM_BOT_TOKEN ?? '',
      webhookSecret: env.TELEGRAM_WEBHOOK_SECRET ?? '',
      botUsername: env.TELEGRAM_BOT_USERNAME ?? null,
      appName: env.TELEGRAM_2FA_APP_NAME ?? defaults.appName,
      codeTtl: num(env.TELEGRAM_2FA_CODE_TTL, defaults.codeTtl),
      cooldown: num(env.TELEGRAM_2FA_COOLDOWN, defaults.cooldown),
      maxAttempts: num(env.TELEGRAM_2FA_MAX_ATTEMPTS, defaults.maxAttempts),
      hashPepper: env.TELEGRAM_2FA_HASH_PEPPER ?? '',
    })
  }

  key(kind: string, id: string): string {
    return `${this.keyPrefix}:${kind}:${id}`
  }

  deepLinkUrl(token: string): string | null {
    if (this.botUsername === null) {
      return null
    }

    return `https://t.me/${this.botUsername}?start=${token}`
  }
}
