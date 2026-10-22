import type { Config } from '../config.js'
import {
  type Clock,
  type CodeStore,
  type Logger,
  type Messages,
  type TelegramClient,
  isVerified,
  nullLogger,
  systemClock,
} from '../contracts.js'
import { ErrorCode } from '../errors.js'
import type { TelegramTwoFactor } from '../telegram-two-factor.js'

export interface TelegramUpdate {
  update_id?: number | string
  message?: {
    message_id?: number
    text?: string
    chat?: { id?: number | string; type?: string }
  }
  callback_query?: {
    id?: string
    data?: string
    message?: { chat?: { id?: number | string; type?: string } }
  }
}

export type CommandHandler = (chatId: string, argument: string) => void | Promise<void>

export interface UpdateHandlerOptions {
  tfa: TelegramTwoFactor
  config: Config
  store: CodeStore
  telegram: TelegramClient
  messages: Messages
  logger?: Logger
  clock?: Clock
  /**
   * Produces the label shown in the link confirmation message. The default
   * shows nothing identifying. Pass something partially masked if you want it:
   * that message lands in a chat.
   */
  accountLabel?: (userId: string) => string | Promise<string>
}

/**
 * Turns a verified Telegram update into protocol actions.
 *
 * Framework-free: hand it a parsed update and it does the work. Routing, body
 * parsing and the secret-token check belong to the caller - see
 * WebhookVerifier and the Express example.
 *
 * Commands: /start (with or without a deeplink payload), /code, /status,
 * /link, /unlink, /help. Anything else gets a short reply rather than silence,
 * because silence from a security bot reads as a broken security bot.
 */
export class UpdateHandler {
  private readonly tfa: TelegramTwoFactor
  private readonly config: Config
  private readonly store: CodeStore
  private readonly telegram: TelegramClient
  private readonly messages: Messages
  private readonly logger: Logger
  private readonly clock: Clock
  private readonly accountLabel: ((userId: string) => string | Promise<string>) | undefined
  private readonly extraCommands = new Map<string, CommandHandler>()

  constructor(options: UpdateHandlerOptions) {
    this.tfa = options.tfa
    this.config = options.config
    this.store = options.store
    this.telegram = options.telegram
    this.messages = options.messages
    this.logger = options.logger ?? nullLogger
    this.clock = options.clock ?? systemClock
    this.accountLabel = options.accountLabel
  }

  /**
   * Register an application command, for example /balance.
   *
   * The handler runs only after the update has been verified as coming from
   * Telegram, but the argument is still user input: treat it as such.
   */
  on(command: string, handler: CommandHandler): this {
    this.extraCommands.set(command.replace(/^\//, '').toLowerCase(), handler)

    return this
  }

  /**
   * Handle one update.
   *
   * @returns whether the update was acted on. Either way the caller should
   *          answer 200: a non-2xx makes Telegram retry and queue every later
   *          update behind this one.
   */
  async handle(update: TelegramUpdate): Promise<boolean> {
    if (await this.isDuplicate(update)) {
      return false
    }

    if (update.callback_query !== undefined) {
      return this.handleCallback(update.callback_query)
    }

    const message = update.message

    if (message === undefined) {
      return false
    }

    const chatId = this.chatIdOf(message.chat)
    const text = typeof message.text === 'string' ? message.text.trim() : ''

    if (chatId === null || text === '') {
      return false
    }

    // Private chats only. A bot added to a group would otherwise hand out
    // verification codes in front of every member of it.
    if ((message.chat?.type ?? 'private') !== 'private') {
      return false
    }

    if (!text.startsWith('/')) {
      // Codes travel application-to-user, never user-to-bot, so free text is
      // not a code to check. Nudging rather than parsing also means a user who
      // pastes a code into the wrong window has not handed it to the bot.
      await this.telegram.sendMessage(chatId, this.messages.unknownCommand())

      return false
    }

    const [command, argument] = this.parseCommand(text)

    this.logger.info('telegram-2fa: command', { command, updateId: update.update_id })

    switch (command) {
      case 'start':
        return this.start(chatId, argument)
      case 'code':
      case 'otp':
      case '2fa':
        return this.code(chatId)
      case 'status':
        return this.status(chatId)
      case 'link':
        return this.link(chatId)
      case 'unlink':
      case 'help':
        return this.help(chatId)
      default:
        return this.dispatchExtra(command, chatId, argument)
    }
  }

  // ------------------------------------------------------------- commands

  private async start(chatId: string, payload: string): Promise<boolean> {
    if (payload === '') {
      return this.help(chatId)
    }

    const result = await this.tfa.completeDeepLink(payload, chatId)

    if (result.ok && result.identity !== undefined) {
      const label =
        this.accountLabel !== undefined
          ? await this.accountLabel(result.identity.userId)
          : 'your account'

      await this.telegram.sendMessage(
        chatId,
        this.messages.linkSucceeded(label, this.config.appName),
      )

      return true
    }

    await this.telegram.sendMessage(
      chatId,
      result.error === ErrorCode.AlreadyLinked
        ? this.messages.alreadyLinked()
        : this.messages.linkTokenInvalid(),
    )

    return false
  }

  private async link(chatId: string): Promise<boolean> {
    if (isVerified(await this.tfa.identityForChat(chatId))) {
      await this.telegram.sendMessage(chatId, this.messages.alreadyLinked())

      return false
    }

    const request = await this.tfa.startPasteLink(chatId)

    await this.telegram.sendMessage(
      chatId,
      this.messages.linkInstructions(request.token, this.config.linkTtl, this.config.appName),
    )

    return true
  }

  private async code(chatId: string): Promise<boolean> {
    // pull() sends the code itself, so the plaintext never reaches this class.
    const result = await this.tfa.pull(chatId)

    if (result.ok) {
      return true
    }

    const text =
      result.error === ErrorCode.NotLinked
        ? this.messages.notLinked(this.config.appName)
        : result.error === ErrorCode.Cooldown
          ? this.messages.cooldown(Math.max(0, (result.nextSendAt ?? 0) - this.clock.now()))
          : this.messages.unknownCommand()

    await this.telegram.sendMessage(chatId, text)

    return false
  }

  private async status(chatId: string): Promise<boolean> {
    const linked = isVerified(await this.tfa.identityForChat(chatId))

    await this.telegram.sendMessage(
      chatId,
      linked
        ? this.messages.welcome(true, this.config.appName)
        : this.messages.notLinked(this.config.appName),
    )

    return true
  }

  /**
   * /help, and /unlink.
   *
   * Unlinking is not done from the chat: whoever holds the phone can already
   * read the codes, and letting them also remove the factor with no session and
   * no password turns a stolen phone into a permanently weakened account.
   */
  private async help(chatId: string): Promise<boolean> {
    const linked = isVerified(await this.tfa.identityForChat(chatId))

    await this.telegram.sendMessage(chatId, this.messages.welcome(linked, this.config.appName))

    return true
  }

  private async dispatchExtra(
    command: string,
    chatId: string,
    argument: string,
  ): Promise<boolean> {
    const handler = this.extraCommands.get(command)

    if (handler === undefined) {
      await this.telegram.sendMessage(chatId, this.messages.unknownCommand())

      return false
    }

    await handler(chatId, argument)

    return true
  }

  // ------------------------------------------------------------- plumbing

  private async handleCallback(
    callbackQuery: NonNullable<TelegramUpdate['callback_query']>,
  ): Promise<boolean> {
    const id = callbackQuery.id ?? ''
    const data = callbackQuery.data ?? ''
    const chatId = this.chatIdOf(callbackQuery.message?.chat)

    if (id !== '') {
      // Acknowledge first, or the user's client spins for ten seconds.
      await this.telegram.answerCallbackQuery(id)
    }

    if (chatId === null) {
      return false
    }

    switch (data) {
      case 'code':
        return this.code(chatId)
      case 'status':
        return this.status(chatId)
      case 'link':
        return this.link(chatId)
      case 'help':
        return this.help(chatId)
      default:
        return false
    }
  }

  private parseCommand(text: string): [string, string] {
    const match = /^(\S+)\s*([\s\S]*)$/.exec(text)
    let command = (match?.[1] ?? '').replace(/^\//, '').toLowerCase()

    // In groups Telegram appends the bot name: /code@kampe_bot.
    if (command.includes('@')) {
      command = command.split('@')[0] ?? command
    }

    return [command, (match?.[2] ?? '').trim()]
  }

  private chatIdOf(chat: { id?: number | string } | undefined): string | null {
    const id = chat?.id

    return typeof id === 'number' || typeof id === 'string' ? String(id) : null
  }

  /**
   * Telegram retries an update it believes was not delivered, so the same
   * update_id can arrive twice. Without this guard a retried /code mints a
   * second code and resets the cooldown.
   */
  private async isDuplicate(update: TelegramUpdate): Promise<boolean> {
    if (!this.config.dedupeUpdates) {
      return false
    }

    const updateId = update.update_id

    if (updateId === undefined) {
      return false
    }

    const key = this.config.key('update', String(updateId))

    if ((await this.store.get(key)) !== null) {
      this.logger.info('telegram-2fa: duplicate update dropped', { updateId })

      return true
    }

    await this.store.put(key, 1, this.config.updateDedupeTtl)

    return false
  }
}
