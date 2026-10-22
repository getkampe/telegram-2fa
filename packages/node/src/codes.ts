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
 * A fast keyed hash is the right primitive here and not a shortcut. These codes
 * live for minutes, are single-use, and are bounded by an attempt limit; a
 * password KDF would add latency to every verification and buy nothing against
 * a six-digit input.
 *
 * What does the work is the key, not the hash. A six-digit code has only a
 * million possible values, so an unkeyed SHA-256 of one is reversed by a table
 * anyone can build in seconds - which is why the pepper is required rather than
 * recommended, and why the application's own secret must not live in the same
 * store as the hashes.
 *
 * The context argument binds a digest to the account it belongs to, so a stolen
 * digest cannot be matched against another user's, and an attacker who dumps the
 * store needs a fresh search per account rather than one table for all of them.
 */
export class CodeHasher {
  constructor(
    private readonly algorithm = 'sha256',
    /**
     * The HMAC key. Required: see the class comment for why an unkeyed digest
     * of a six-digit code protects nothing. Config enforces a minimum length,
     * so this is never empty in practice.
     */
    private readonly pepper = '',
  ) {}

  /**
   * @param context Data the digest is bound to - the user id for a challenge
   * code. Must be identical at verification or the comparison cannot match.
   */
  hash(code: string, context = ''): string {
    // A NUL separator, so that ("ab", "c") and ("a", "bc") cannot produce the
    // same input. Neither value can contain a NUL byte.
    return createHmac(this.algorithm, this.pepper)
      .update(`${context}\0${code}`)
      .digest('hex')
  }

  /**
   * Constant-time comparison of a candidate against a stored hash.
   *
   * Not ===. On secret material a comparison that returns at the first
   * differing byte is a timing oracle. Both operands are fixed-length hex here,
   * so the length check below never rejects a legitimate code.
   */
  matches(storedHash: string, candidate: string, context = ''): boolean {
    const expected = Buffer.from(storedHash, 'utf8')
    const actual = Buffer.from(this.hash(candidate, context), 'utf8')

    if (expected.length !== actual.length) {
      return false
    }

    return timingSafeEqual(expected, actual)
  }
}
