<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Codes;

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
 * anyone can build in seconds — which is why the pepper is required rather than
 * recommended, and why the application's own secret must not live in the same
 * store as the hashes.
 *
 * The context argument binds a digest to the account it belongs to, so a stolen
 * digest cannot be matched against another user's, and an attacker who dumps the
 * store needs a fresh search per account rather than one table for all of them.
 */
class CodeHasher
{
    public function __construct(
        private readonly string $algorithm = 'sha256',
        /**
         * The HMAC key. Required: see the class comment for why an unkeyed
         * digest of a six-digit code protects nothing. Config enforces a
         * minimum length, so this is never empty in practice.
         */
        private readonly string $pepper = '',
    ) {
    }

    /**
     * @param  string  $context  Data the digest is bound to — the user id for a
     *                           challenge code. Must be identical at
     *                           verification or the comparison cannot match.
     */
    public function hash(string $code, string $context = ''): string
    {
        // A NUL separator, so that ("ab", "c") and ("a", "bc") cannot produce
        // the same input. Neither value can contain a NUL byte.
        return hash_hmac($this->algorithm, $context . "\0" . $code, $this->pepper);
    }

    /**
     * Constant-time comparison of a candidate code against a stored hash.
     *
     * hash_equals, not ===. On secret material a comparison that returns at the
     * first differing byte is a timing oracle, and in PHP == on two
     * numeric-looking strings compares them as numbers, so '0123456' would
     * equal '123456.0'. Comparing fixed-length hex digests removes both.
     */
    public function matches(string $storedHash, string $candidate, string $context = ''): bool
    {
        return hash_equals($storedHash, $this->hash($candidate, $context));
    }
}
