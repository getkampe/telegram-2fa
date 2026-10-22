import { createHmac, randomInt, timingSafeEqual } from 'node:crypto'

/**
 * The alphabet for link codes a human has to retype.
 *
 * Crockford base32: no I, L, O or U, so there is no 1/I or 0/O confusion when
 * someone reads a code off one screen and types it into another.
 */
export const LINK_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** URL-safe alphabet for deeplink nonces, which are never retyped by hand. */
export const TOKEN_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'

/**
 * Generates the three kinds of secret this protocol uses.
 *
 * Everything here draws from node:crypto. Math.random is seeded and
 * predictable: for a 2FA code that means an attacker who has seen a few codes
 * can produce the next one, and it is not faster in any way that matters.
 */
export class CodeGenerator {
  /**
   * A numeric 2FA code, zero-padded.
   *
   * Numeric is safe for this one because the store key is scoped to a single
   * user (SPEC.md section 6), so guessing is bounded by the attempt budget
   * rather than by the size of the alphabet.
   */
  twoFactorCode(length = 6): string {
    const max = 10 ** length
    return String(randomInt(0, max)).padStart(length, '0')
  }

  /**
   * A link code for the paste flow.
   *
   * Not numeric: the paste flow's store key is derived from the code itself, so
   * every outstanding code shares one namespace. Eight base32 characters is
   * 40 bits.
   */
  linkCode(length = 8): string {
    return this.fromAlphabet(LINK_ALPHABET, length)
  }

  /** A deeplink nonce. 32 characters of a 64-symbol alphabet is 192 bits. */
  deepLinkToken(length = 32): string {
    return this.fromAlphabet(TOKEN_ALPHABET, length)
  }

  /** A webhook secret token, in the character set Telegram accepts. */
  webhookSecret(length = 48): string {
    return this.fromAlphabet(TOKEN_ALPHABET, length)
  }

  private fromAlphabet(alphabet: string, length: number): string {
    let out = ''
    for (let i = 0; i < length; i++) {
      out += alphabet[randomInt(0, alphabet.length)]
    }
    return out
  }
}

/**
 * Hashing and comparison of code material.
 *
 * A fast hash is correct here: these codes live for minutes, are single-use and
 * are attempt-budgeted. The hash exists so a dumped store or a leaked log yields
 * nothing replayable, not to resist offline cracking, and a password KDF would
 * add latency to every verification for no gain against a six-digit input.
 */
export class CodeHasher {
  constructor(
    private readonly algorithm = 'sha256',
    /**
     * Optional application-wide pepper. With one set, a store dump cannot be
     * matched against a precomputed table of all six-digit hashes - which, for
     * six digits, is a table anyone can build in seconds.
     */
    private readonly pepper = '',
  ) {}

  hash(code: string): string {
    return createHmac(this.algorithm, this.pepper).update(code).digest('hex')
  }

  /**
   * Constant-time comparison of a candidate against a stored hash.
   *
   * Not ===. On secret material a comparison that returns at the first
   * differing byte is a timing oracle. Both operands are fixed-length hex here,
   * so the length check below never rejects a legitimate code.
   */
  matches(storedHash: string, candidate: string): boolean {
    const expected = Buffer.from(storedHash, 'utf8')
    const actual = Buffer.from(this.hash(candidate), 'utf8')

    if (expected.length !== actual.length) {
      return false
    }

    return timingSafeEqual(expected, actual)
  }
}
