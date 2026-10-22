import type { Messages } from '../contracts.js'

/**
 * Escape text for parse_mode HTML.
 *
 * Telegram's HTML mode needs only these three characters escaped. Any message
 * that interpolates a display name, an email or anything else a user controls
 * must run it through here: unescaped, a name containing an angle bracket makes
 * Telegram reject the message outright, which is the benign case.
 */
export function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

function humanise(seconds: number): string {
  if (seconds < 60) {
    return `${seconds} second${seconds === 1 ? '' : 's'}`
  }

  const minutes = Math.round(seconds / 60)

  return `${minutes} minute${minutes === 1 ? '' : 's'}`
}

/**
 * The bot's default English copy. Implement Messages to translate or restyle.
 */
export class DefaultMessages implements Messages {
  code(code: string, ttlSeconds: number): string {
    return (
      '🔐 <b>Verification code</b>\n\n' +
      `<code>${code}</code>\n\n` +
      `Valid for ${humanise(ttlSeconds)}, once.\n` +
      'If you did not ask for this, someone has your password. ' +
      'Do not enter the code, and change it now.'
    )
  }

  linkInstructions(code: string, ttlSeconds: number, appName: string): string {
    return (
      `🔗 <b>Link this chat to ${escapeHtml(appName)}</b>\n\n` +
      `<code>${code}</code>\n\n` +
      'Enter this code on the Telegram setup page in your account settings.\n' +
      `It expires in ${humanise(ttlSeconds)}. Tap it to copy.`
    )
  }

  linkSucceeded(accountLabel: string, appName: string): string {
    return (
      `✅ <b>This chat is now your second factor for ${escapeHtml(appName)}</b>\n\n` +
      `Account: ${escapeHtml(accountLabel)}\n\n` +
      'Send /code any time you need a verification code.\n' +
      'If you did not do this, send /unlink immediately and change your password.'
    )
  }

  linkTokenInvalid(): string {
    return (
      '❌ <b>That code did not work</b>\n\n' +
      'It has expired, has already been used, or was mistyped.\n\n' +
      'Start again from your account settings to get a fresh one.'
    )
  }

  alreadyLinked(): string {
    return (
      'ℹ️ <b>Already linked</b>\n\n' +
      'This chat is already set up as a second factor.\n\n' +
      'Send /code for a verification code, or /unlink to remove it.'
    )
  }

  notLinked(appName: string): string {
    return (
      '🔌 <b>This chat is not linked</b>\n\n' +
      `Open your ${escapeHtml(appName)} account settings and start the Telegram setup, ` +
      'then come back here.'
    )
  }

  cooldown(secondsRemaining: number): string {
    return (
      '⏳ <b>A code was just sent</b>\n\n' +
      `Check the message above, or ask again in ${humanise(secondsRemaining)}.`
    )
  }

  unlinkInstructions(appName: string): string {
    return (
      '🔓 <b>Removing Telegram as your second factor</b>\n\n' +
      'For your security this cannot be done from the chat — anyone holding your phone ' +
      'could do it.\n\n' +
      `1. Sign in to ${escapeHtml(appName)} and open your security settings\n` +
      '2. Choose to remove Telegram\n' +
      '3. Send /code here and enter that code to confirm\n\n' +
      'Lost access to this account instead? Contact support — they can verify you another way.'
    )
  }

  unlinked(appName: string): string {
    return (
      '🔓 <b>No longer your second factor</b>\n\n' +
      `This chat has been unlinked from ${escapeHtml(appName)}.\n\n` +
      'If you did not do this, your account may be compromised: sign in, change your ' +
      'password, and set up two-factor authentication again.'
    )
  }

  welcome(isLinked: boolean, appName: string): string {
    const name = escapeHtml(appName)

    if (isLinked) {
      return (
        `👋 <b>${name} security bot</b>\n\n` +
        'This chat is linked and working.\n\n' +
        '/code — get a verification code\n' +
        '/status — show link details\n' +
        '/unlink — stop using this chat as a second factor\n' +
        '/help — this message'
      )
    }

    return (
      `👋 <b>${name} security bot</b>\n\n` +
      `I deliver verification codes for your ${name} account.\n\n` +
      'To get started, open your account settings, begin the Telegram setup, and follow ' +
      'the link or code it gives you.\n\n' +
      '/help — this message'
    )
  }

  unknownCommand(): string {
    return '🤔 <b>I do not know that command</b>\n\nSend /help to see what I can do.'
  }
}
