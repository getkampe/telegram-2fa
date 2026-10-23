using System.Security.Cryptography;
using System.Text;

namespace Kampe.TelegramTwoFactor;

/// <summary>
/// Generates the kinds of secret this protocol uses.
/// </summary>
/// <remarks>
/// Everything here draws from <see cref="RandomNumberGenerator"/>.
/// <see cref="Random"/>, including its shared instance, is not cryptographic:
/// its output is predictable from prior samples, which for a 2FA code means an
/// attacker who has seen enough codes can produce the next one. It is not faster
/// in any way that matters here.
/// </remarks>
public class CodeGenerator
{
    /// <summary>
    /// Crockford base32: no I, L, O or U, so there is no 1/I or 0/O confusion when
    /// someone reads a code off one screen and types it into another.
    /// </summary>
    public const string LinkAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>URL-safe alphabet for deeplink nonces, which are never retyped by hand.</summary>
    public const string TokenAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

    /// <summary>
    /// A numeric 2FA code, zero-padded.
    /// </summary>
    /// <remarks>
    /// Numeric is safe for this one because the store key is scoped to a single
    /// user (SPEC.md section 6), so guessing is bounded by the attempt budget
    /// rather than by the size of the alphabet.
    /// </remarks>
    public virtual string TwoFactorCode(int length = 6)
    {
        var bound = (int)Math.Pow(10, length);

        return RandomNumberGenerator.GetInt32(bound).ToString($"D{length}",
            System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// A link code for the paste flow.
    /// </summary>
    /// <remarks>
    /// Not numeric: the paste flow's store key is derived from the code itself, so
    /// every outstanding code shares one namespace. Eight base32 characters is 40
    /// bits.
    /// </remarks>
    public virtual string LinkCode(int length = 8) => FromAlphabet(LinkAlphabet, length);

    /// <summary>A deeplink nonce. 32 characters of a 64-symbol alphabet is 192 bits.</summary>
    public virtual string DeepLinkToken(int length = 32) => FromAlphabet(TokenAlphabet, length);

    /// <summary>A webhook secret token, in the character set Telegram accepts.</summary>
    public virtual string WebhookSecret(int length = 48) => FromAlphabet(TokenAlphabet, length);

    /// <summary>
    /// A fresh enrollment generation: 128 bits, hex.
    /// </summary>
    /// <remarks>
    /// Random rather than a counter: nothing needs ordering, only inequality, and a
    /// random value cannot be predicted from the ones before it.
    /// </remarks>
    public virtual string EnrollmentGeneration() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    /// <summary>
    /// Identifies one particular challenge, so a cleanup for a failed delivery can
    /// tell its own code from a newer one.
    /// </summary>
    public virtual string ChallengeId() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

    private static string FromAlphabet(string alphabet, int length)
    {
        var buffer = new char[length];

        for (var i = 0; i < length; i++)
        {
            buffer[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        }

        return new string(buffer);
    }
}

/// <summary>
/// Hashing and comparison of code material.
/// </summary>
/// <remarks>
/// A fast keyed hash is the right primitive and not a shortcut. These codes live
/// for minutes, are single-use, and are bounded by an attempt limit; a password
/// KDF would add latency to every verification and buy nothing against a
/// six-digit input.
/// <para>
/// What does the work is the key, not the hash. A six-digit code has only a
/// million possible values, so an unkeyed SHA-256 of one is reversed by a table
/// anyone can build in seconds - which is why the pepper is required rather than
/// recommended, and why the application's own secret must not live in the same
/// store as the hashes.
/// </para>
/// <para>
/// The context argument binds a digest to the account it belongs to, so a stolen
/// digest cannot be matched against another user's, and an attacker who dumps the
/// store needs a fresh search per account rather than one table for all of them.
/// </para>
/// </remarks>
public class CodeHasher
{
    private readonly string _algorithm;
    private readonly byte[] _pepper;

    /// <summary>Creates a hasher.</summary>
    public CodeHasher(string algorithm = "sha256", string pepper = "")
    {
        _algorithm = algorithm;
        _pepper = Encoding.UTF8.GetBytes(pepper);
    }

    /// <summary>
    /// HMAC over context + NUL + code.
    /// </summary>
    /// <remarks>
    /// The NUL separator means ("ab", "c") and ("a", "bc") cannot produce the same
    /// input; neither value can contain a NUL byte.
    /// </remarks>
    public virtual string Hash(string code, string context = "")
    {
        var message = Encoding.UTF8.GetBytes($"{context}\0{code}");

        return Convert.ToHexString(Mac(message)).ToLowerInvariant();
    }

    /// <summary>
    /// Fixed-time comparison.
    /// </summary>
    /// <remarks>
    /// On secret material a comparison that returns at the first differing byte is
    /// a timing oracle. The length check comes first because
    /// <see cref="CryptographicOperations.FixedTimeEquals"/> is only fixed-time for
    /// equal lengths, and a digest's length is not itself a secret.
    /// </remarks>
    public virtual bool Matches(string? storedHash, string candidate, string context = "")
    {
        if (storedHash is null)
        {
            return false;
        }

        var expected = Encoding.UTF8.GetBytes(storedHash);
        var actual = Encoding.UTF8.GetBytes(Hash(candidate, context));

        return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    private byte[] Mac(byte[] message) => _algorithm.ToLowerInvariant() switch
    {
        "sha256" => HMACSHA256.HashData(_pepper, message),
        "sha384" => HMACSHA384.HashData(_pepper, message),
        "sha512" => HMACSHA512.HashData(_pepper, message),
        _ => throw new ConfigurationException($"Unknown hash algorithm \"{_algorithm}\"."),
    };

    /// <summary>Whether an algorithm name is one this hasher supports.</summary>
    public static bool Supports(string algorithm) =>
        algorithm.ToLowerInvariant() is "sha256" or "sha384" or "sha512";
}

/// <summary>Fixed-time comparison of non-secret-length strings.</summary>
internal static class ConstantTime
{
    /// <summary>Whether two strings are equal, without an early return.</summary>
    internal static bool Equals(string? left, string? right)
    {
        if (left is null || right is null)
        {
            return false;
        }

        var a = Encoding.UTF8.GetBytes(left);
        var b = Encoding.UTF8.GetBytes(right);

        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }
}
