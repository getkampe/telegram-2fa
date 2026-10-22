/**
 * @kampe/telegram-2fa
 *
 * Telegram as a second authentication factor. Zero runtime dependencies; the
 * protocol it implements is specified in SPEC.md at the root of the repository,
 * and the PHP package in the same repository implements the same one.
 *
 * Minimal wiring:
 *
 * ```ts
 * const tfa = new TelegramTwoFactor({
 *   config: Config.fromEnv(),
 *   store: new RedisCodeStore(redis),
 *   identities: myIdentityStore,
 *   telegram: new FetchTelegramClient({ botToken: process.env.TELEGRAM_BOT_TOKEN! }),
 *   messages: new DefaultMessages(),
 * })
 * ```
 */

export { Config, type ConfigInput } from './config.js'

export {
  CodeGenerator,
  CodeHasher,
  LINK_ALPHABET,
  TOKEN_ALPHABET,
} from './codes.js'

export {
  type Clock,
  type CodeStore,
  type Identity,
  type IdentityStore,
  type InlineButton,
  type Logger,
  type Messages,
  type TelegramClient,
  FrozenClock,
  isVerified,
  nullLogger,
  systemClock,
} from './contracts.js'

export {
  ChatAlreadyLinked,
  ConfigurationError,
  ErrorCode,
  TelegramRequestFailed,
  TelegramTwoFactorError,
  errorMessages,
} from './errors.js'

export {
  type ChallengeResult,
  type LinkRequest,
  type LinkResult,
  type TelegramTwoFactorOptions,
  type VerificationResult,
  TelegramTwoFactor,
} from './telegram-two-factor.js'

export { MemoryCodeStore, MemoryIdentityStore } from './stores/memory.js'
export { type RedisLike, RedisCodeStore } from './stores/redis.js'

export {
  type FetchTelegramClientOptions,
  FetchTelegramClient,
} from './telegram/fetch-client.js'
export { DefaultMessages, escapeHtml } from './telegram/messages.js'

export { SECRET_HEADER, TELEGRAM_RANGES, WebhookVerifier } from './webhook/verifier.js'
export {
  type CommandHandler,
  type TelegramUpdate,
  type UpdateHandlerOptions,
  UpdateHandler,
} from './webhook/update-handler.js'
