<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Codes;

/**
 * Hashing and comparison of code material.
 *
 * A fast hash is the right choice here and not a shortcut. These codes live for
 * five minutes, are single-use, and are bounded by an attempt limit; the hash is
 * there so that a dumped Redis instance or a leaked log file yields nothing
 * replayable, not to withstand offline cracking. A password KDF would add latency
 * to every verification and buy nothing against a six-digit input.
 */
class CodeHasher
{
    public function __construct(
        private readonly string $algorithm = 'sha256',
        /**
         * Optional application-wide pepper. With it, a store dump cannot be
         * matched against a precomputed table of all six-digit hashes - which,
         * for a six-digit space, is a table anyone can build in seconds.
         */
        private readonly string $pepper = '',
    ) {
    }

    public function hash(string $code): string
    {
        return hash_hmac($this->algorithm, $code, $this->pepper);
    }

    /**
     * Constant-time comparison of a candidate code against a stored hash.
     *
     * hash_equals, not ===. On secret material a byte-by-byte comparison that
     * returns early is a timing oracle, and in PHP == on two numeric-looking
     * strings compares them as numbers, so '0123456' == '123456.0' is true. Both
     * problems disappear by comparing fixed-length hex digests with hash_equals.
     */
    public function matches(string $storedHash, string $candidate): bool
    {
        return hash_equals($storedHash, $this->hash($candidate));
    }
}
