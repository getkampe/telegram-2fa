<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Codes;

/**
 * Generates the three kinds of secret this protocol uses.
 *
 * Every method draws from random_int, which is a CSPRNG. rand and mt_mrand are
 * seeded pseudo-random generators: their output is predictable from a few prior
 * samples, which for a 2FA code means an attacker who has seen a handful of codes
 * can produce the next one. There is no performance reason to prefer them here.
 */
class CodeGenerator
{
    /**
     * The alphabet for link codes a human has to retype.
     *
     * Crockford base32: no I, L, O or U, so there is no 1/I, 0/O or rude-word
     * confusion when a user reads a code off one screen and types it into another.
     */
    public const LINK_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    /** URL-safe alphabet for deeplink nonces, which are never retyped by hand. */
    public const TOKEN_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';

    /**
     * A numeric 2FA code, zero-padded to the requested length.
     *
     * Numeric is safe for this one because the store key is scoped to a single
     * user (SPEC.md section 6), so the guessing budget is per account and is
     * bounded by the attempt limit rather than by the size of the alphabet.
     */
    public function twoFactorCode(int $length = 6): string
    {
        $max = (10 ** $length) - 1;

        return str_pad((string) random_int(0, $max), $length, '0', STR_PAD_LEFT);
    }

    /**
     * A link code for the paste flow.
     *
     * Not numeric, because the paste flow's store key is derived from the code
     * itself and therefore shares one namespace across all users, which makes a
     * short numeric code enumerable. Eight base32 characters is 40 bits.
     */
    public function linkCode(int $length = 8): string
    {
        return $this->fromAlphabet(self::LINK_ALPHABET, $length);
    }

    /**
     * A deeplink nonce. 32 characters of a 64-symbol alphabet is 192 bits.
     */
    public function deepLinkToken(int $length = 32): string
    {
        return $this->fromAlphabet(self::TOKEN_ALPHABET, $length);
    }

    /**
     * A webhook secret token, in the character set Telegram accepts.
     */
    public function webhookSecret(int $length = 48): string
    {
        return $this->fromAlphabet(self::TOKEN_ALPHABET, $length);
    }

    private function fromAlphabet(string $alphabet, int $length): string
    {
        $max = strlen($alphabet) - 1;
        $out = '';

        for ($i = 0; $i < $length; $i++) {
            $out .= $alphabet[random_int(0, $max)];
        }

        return $out;
    }
}
