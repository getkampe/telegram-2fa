import { timingSafeEqual } from 'node:crypto'
import type { Config } from '../config.js'

/** Telegram's published webhook source ranges. */
export const TELEGRAM_RANGES = ['149.154.160.0/20', '91.108.4.0/22'] as const

/** The header Telegram sends the secret token in. */
export const SECRET_HEADER = 'x-telegram-bot-api-secret-token'

/**
 * Decides whether a request on the webhook endpoint really came from Telegram.
 *
 * This is the most important check in the library. The webhook URL is public and
 * unauthenticated, and what it accepts is an assertion of the form "this chat id
 * is asking for a code". Without verification, anyone who learns the URL can post
 * an update carrying a chat id and have the bot mint a code for whichever account
 * that chat is linked to - and because the code then arrives in the real owner's
 * chat, nothing in the application looks wrong.
 *
 * Telegram supports this directly: register the webhook with a secret_token and
 * it sends that token in a header on every request.
 */
export class WebhookVerifier {
  constructor(private readonly config: Config) {}

  /**
   * @param headerValue The x-telegram-bot-api-secret-token header.
   * @param remoteIp    The connecting address, when IP restriction is on.
   */
  accepts(headerValue: string | null | undefined, remoteIp?: string | null): boolean {
    if (headerValue == null || headerValue === '') {
      return false
    }

    const expected = Buffer.from(this.config.webhookSecret, 'utf8')
    const actual = Buffer.from(headerValue, 'utf8')

    // Length is checked first because timingSafeEqual throws on a mismatch.
    // That leaks the secret's length, which is not a secret.
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      return false
    }

    if (this.config.restrictWebhookIps && !this.fromTelegram(remoteIp)) {
      return false
    }

    return true
  }

  /**
   * Whether an address falls inside Telegram's published ranges.
   *
   * Only meaningful if remoteIp is the real peer. Behind a load balancer the
   * peer is the proxy and the client address comes from a header the caller can
   * set at will, which is why this is off by default and the secret token is
   * not.
   */
  fromTelegram(remoteIp: string | null | undefined): boolean {
    if (remoteIp == null) {
      return false
    }

    const ip = this.toLong(remoteIp)

    if (ip === null) {
      return false
    }

    return TELEGRAM_RANGES.some((cidr) => {
      const [subnet, bits] = cidr.split('/')
      const subnetLong = this.toLong(subnet!)

      if (subnetLong === null) {
        return false
      }

      const mask = bits === '0' ? 0 : (-1 << (32 - Number(bits))) >>> 0

      return (ip & mask) >>> 0 === (subnetLong & mask) >>> 0
    })
  }

  private toLong(ip: string): number | null {
    const parts = ip.split('.')

    if (parts.length !== 4) {
      return null
    }

    let long = 0

    for (const part of parts) {
      if (!/^\d{1,3}$/.test(part)) {
        return null
      }

      const octet = Number(part)

      if (octet > 255) {
        return null
      }

      long = (long << 8) | octet
    }

    return long >>> 0
  }
}
