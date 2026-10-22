/**
 * The error vocabulary of SPEC.md section 10.
 *
 * These strings are the wire form of the protocol, shared with every other
 * implementation, so a client written against them works against any of them.
 * Do not change the values.
 */
export const ErrorCode = {
  /** The account has no verified Telegram link. */
  NotLinked: 'not_linked',
  /** The account, or the chat, is already linked. */
  AlreadyLinked: 'already_linked',
  /** A code was sent too recently. The result carries the next send time. */
  Cooldown: 'cooldown',
  /** Telegram did not accept the message. */
  SendFailed: 'send_failed',
  /** The submitted code does not match. */
  Invalid: 'invalid',
  /** No live code for this account: never issued, aged out, or already used. */
  Expired: 'expired',
  /** The attempt budget for this code is exhausted and the code is now dead. */
  TooManyAttempts: 'too_many_attempts',
  /** Link token unknown, expired or already used. */
  InvalidToken: 'invalid_token',
  /** Webhook secret token missing or wrong. */
  WebhookUnauthorized: 'webhook_unauthorized',
} as const

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode]

/**
 * Messages safe to show an end user.
 *
 * Deliberately vague about which of "never issued", "expired" and "already
 * used" applies: distinguishing them tells an attacker holding a session
 * whether a challenge is currently in flight.
 */
export const errorMessages: Record<ErrorCode, string> = {
  [ErrorCode.NotLinked]: 'No Telegram account is linked to this profile.',
  [ErrorCode.AlreadyLinked]: 'This Telegram account is already linked.',
  [ErrorCode.Cooldown]: 'A code was just sent. Please wait before requesting another.',
  [ErrorCode.SendFailed]:
    'The code could not be delivered. Please try again or use another method.',
  [ErrorCode.Invalid]: 'That code is not valid.',
  [ErrorCode.Expired]: 'That code is no longer valid. Request a new one.',
  [ErrorCode.TooManyAttempts]: 'Too many incorrect attempts. Request a new code.',
  [ErrorCode.InvalidToken]: 'This link has expired or has already been used.',
  [ErrorCode.WebhookUnauthorized]: 'Unauthorized.',
}

/** Base class for every error this library throws. */
export class TelegramTwoFactorError extends Error {
  override name = 'TelegramTwoFactorError'
}

/**
 * The configuration cannot produce a secure installation.
 *
 * Thrown when the config is built, never mid-request.
 */
export class ConfigurationError extends TelegramTwoFactorError {
  override name = 'ConfigurationError'
}

/** Telegram refused a request, or could not be reached. */
export class TelegramRequestFailed extends TelegramTwoFactorError {
  override name = 'TelegramRequestFailed'
}

/**
 * A chat is already bound to a different user.
 *
 * Identity stores throw this rather than reassigning: one Telegram account
 * acting as the second factor for several accounts means one compromised
 * Telegram account compromises all of them.
 */
export class ChatAlreadyLinked extends TelegramTwoFactorError {
  override name = 'ChatAlreadyLinked'
}
