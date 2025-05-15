
using LibSodium.Interop;
using System.Text;

namespace LibSodium
{
    /// <summary>
    /// Supported password hashing algorithms.
    /// </summary>
    public enum PasswordHashAlgorithm
    {
        /// <summary>
        /// Argon2i version 1.3 — optimized for side-channel resistance.
        /// </summary>
        Argon2i13 = Native.CRYPTO_PWHASH_ALG_ARGON2I13,

        /// <summary>
        /// Argon2id version 1.3 — hybrid mode (default and recommended).
        /// </summary>
        Argon2id13 = Native.CRYPTO_PWHASH_ALG_ARGON2ID13
    }

    /// <summary>
    /// Provides password hashing and key derivation using Argon2.
    /// </summary>
    /// <remarks>
    /// 🧂 Based on libsodium's crypto_pwhash API: https://doc.libsodium.org/password_hashing
    /// </remarks>
    public static class CryptoPasswordHash
    {
		/// <summary>
		/// Minimum allowed length in bytes for the derived key (16).
		/// </summary>
		public const int MinKeyLen = Native.CRYPTO_PWHASH_BYTES_MIN;

		/// <summary>
		/// Minimum allowed password length in bytes (0).
		/// </summary>
		public const int MinPasswordLen = Native.CRYPTO_PWHASH_PASSWD_MIN;

		/// <summary>
		/// Length of the salt in bytes (16).
		/// </summary>
		public const int SaltLen = Native.CRYPTO_PWHASH_SALTBYTES;

		/// <summary>
		/// Maximum length of the encoded hash string (includes null terminator) (128).
		/// </summary>
		public const int EncodedLen = Native.CRYPTO_PWHASH_STRBYTES;

		/// <summary>
		/// Minimum number of iterations for key derivation (1).
		/// </summary>
		public const int MinIterations = Native.CRYPTO_PWHASH_OPSLIMIT_MIN;

		/// <summary>
		/// Recommended iterations for interactive use (2).
		/// </summary>
		public const int InteractiveIterations = Native.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;

		/// <summary>
		/// Recommended iterations for moderate use (3).
		/// </summary>
		public const int ModerateIterations = Native.CRYPTO_PWHASH_OPSLIMIT_MODERATE;

		/// <summary>
		/// Recommended iterations for sensitive use (4).
		/// </summary>
		public const int SensitiveIterations = Native.CRYPTO_PWHASH_OPSLIMIT_SENSITIVE;

		/// <summary>
		/// Minimum memory usage in bytes (8k).
		/// </summary>
		public const int MinMemoryLen = Native.CRYPTO_PWHASH_MEMLIMIT_MIN;

		/// <summary>
		/// Recommended memory usage for interactive use (64Mb).
		/// </summary>
		public const int InteractiveMemoryLen = Native.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;

		/// <summary>
		/// Recommended memory usage for moderate use (256Mb).
		/// </summary>
		public const int ModerateMemoryLen = Native.CRYPTO_PWHASH_MEMLIMIT_MODERATE;

		/// <summary>
		/// Recommended memory usage for sensitive use (1Gb).
		/// </summary>
		public const int SensitiveMemoryLen = Native.CRYPTO_PWHASH_MEMLIMIT_SENSITIVE;

		/// <summary>
		/// Prefix for the encoded hash string (e.g. "$argon2id$").
		/// </summary>
		public const string Prefix = Native.CRYPTO_PWHASH_STRPREFIX;



		/// <summary>
		/// Derives a secret key from a password and salt using Argon2.
		/// </summary>
		/// <param name="key">Buffer to receive the derived key (recommended: 32 bytes).</param>
		/// <param name="password">The password to hash.</param>
		/// <param name="salt">The salt (must be 16 bytes).</param>
		/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
		/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
		/// <param name="algorithm">Hash algorithm to use (default: Argon2id13).</param>
		/// <exception cref="ArgumentException">If arguments are invalid.</exception>
		/// <exception cref="LibSodiumException">If hashing fails.</exception>
		public static void DeriveKey(
            Span<byte> key,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            int iterations = InteractiveIterations,
            int requiredMemoryLen = InteractiveMemoryLen,
            PasswordHashAlgorithm algorithm = PasswordHashAlgorithm.Argon2id13)
        {
			if (key.Length < MinKeyLen)
				throw new ArgumentOutOfRangeException($"Key length must be at least {MinKeyLen} bytes.", nameof(key));

			if (password.Length < MinPasswordLen)
				throw new ArgumentOutOfRangeException($"Password length must be at least {MinPasswordLen} bytes.", nameof(password));

			if (salt.Length != SaltLen)
				throw new ArgumentException($"Salt must be exactly {SaltLen} bytes.", nameof(salt));

			if (iterations < MinIterations)
				throw new ArgumentOutOfRangeException(nameof(iterations), $"Iterations must be at least {MinIterations}.");

			if (requiredMemoryLen < MinMemoryLen)
				throw new ArgumentOutOfRangeException(nameof(requiredMemoryLen), $"Memory length must be at least {MinMemoryLen} bytes.");

			if (algorithm == PasswordHashAlgorithm.Argon2i13 && iterations < 3)
				throw new ArgumentOutOfRangeException(nameof(iterations), "Argon2i13 requires iterations >= 3 for side-channel resistance.");

			LibraryInitializer.EnsureInitialized();

            int result = Native.crypto_pwhash(
                key, (ulong)key.Length,
                password, (ulong)password.Length,
                salt,
                (ulong)iterations, (nuint)requiredMemoryLen, (int)algorithm);

            if (result != 0)
                throw new LibSodiumException("DeriveKey failed. Possible out of memory.");
        }

		/// <summary>
		/// Derives a secret key from a password string and salt using Argon2.
		/// </summary>
		/// <param name="key">Buffer to receive the derived key (recommended: 32 bytes).</param>
		/// <param name="password">The password string to hash.</param>
		/// <param name="salt">The salt (must be 16 bytes).</param>
		/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
		/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
		/// <param name="algorithm">Hash algorithm to use (default: Argon2id13).</param>
		/// <exception cref="ArgumentNullException">If the password is null.</exception>
		/// <exception cref="LibSodiumException">If hashing fails.</exception>
		public static void DeriveKey(
			Span<byte> key,
			string password,
			ReadOnlySpan<byte> salt,
			int iterations = InteractiveIterations,
			int requiredMemoryLen = InteractiveMemoryLen,
			PasswordHashAlgorithm algorithm = PasswordHashAlgorithm.Argon2id13)
		{
			ArgumentNullException.ThrowIfNull(password);

			var passwordUtf8Len = Encoding.UTF8.GetByteCount(password);

			Span<byte> passwordUtf8 = passwordUtf8Len > Constants.MaxStackAlloc ? new byte[passwordUtf8Len]:  stackalloc byte[passwordUtf8Len];
			Encoding.UTF8.GetBytes(password, passwordUtf8);

			DeriveKey(key, passwordUtf8, salt, iterations, requiredMemoryLen, algorithm);
		}

		/// <summary>
		/// Hashes a password into a human-readable string (including algorithm and parameters).
		/// </summary>
		/// <param name="password">The password to hash (in UTF-8).</param>
		/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
		/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
		/// <returns>A string containing only ASCII characters, including the algorithm identifier, salt, and parameters.</returns>
		/// <exception cref="ArgumentOutOfRangeException">If password is too short or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">If hashing fails.</exception>
		public static string HashPassword(
			ReadOnlySpan<byte> password,
			int iterations = InteractiveIterations,
			int requiredMemoryLen = InteractiveMemoryLen)
		{
			if (password.Length < MinPasswordLen)
				throw new ArgumentOutOfRangeException($"Password length must be at least {MinPasswordLen} bytes.", nameof(password));

			if (iterations < MinIterations)
				throw new ArgumentOutOfRangeException(nameof(iterations), $"Iterations must be at least {MinIterations}.");

			if (requiredMemoryLen < MinMemoryLen)
				throw new ArgumentOutOfRangeException(nameof(requiredMemoryLen), $"Memory length must be at least {MinMemoryLen} bytes.");

			Span<byte> buffer = stackalloc byte[EncodedLen];
			int result = Native.crypto_pwhash_str(
				buffer,
				password, (ulong)password.Length,
				(ulong)iterations, (nuint)requiredMemoryLen);

			if (result != 0)
				throw new LibSodiumException("HashPassword failed. Possible out of memory.");

			return Encoding.ASCII.GetString(buffer.Slice(0, buffer.IndexOf((byte)0)));
		}

		/// <summary>
		/// Hashes a password string into a human-readable string (including algorithm and parameters).
		/// </summary>
		/// <param name="password">The password to hash (as string).</param>
		/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
		/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
		/// <returns>A string containing only ASCII characters, including the algorithm identifier, salt, and parameters.</returns>
		/// <exception cref="ArgumentNullException">If the password is null.</exception>
		/// <exception cref="ArgumentOutOfRangeException">If parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">If hashing fails.</exception>
		public static string HashPassword(
			string password,
			int iterations = InteractiveIterations,
			int requiredMemoryLen = InteractiveMemoryLen)
		{
			ArgumentNullException.ThrowIfNull(password);

			var passwordUtf8Len = Encoding.UTF8.GetByteCount(password);
			Span<byte> passwordUtf8 = passwordUtf8Len > Constants.MaxStackAlloc ? new byte[passwordUtf8Len] : stackalloc byte[passwordUtf8Len];
			Encoding.UTF8.GetBytes(password, passwordUtf8);

			return HashPassword(passwordUtf8, iterations, requiredMemoryLen);
		}

		/// <summary>
		/// Verifies a password against a previously hashed string.
		/// </summary>
		/// <param name="hashedPassword">The encoded password hash string (must be ASCII and null-terminated).</param>
		/// <param name="password">The password to verify.</param>
		/// <returns><c>true</c> if the password is valid; otherwise, <c>false</c>.</returns>
		/// <exception cref="ArgumentNullException">If <paramref name="hashedPassword"/> is null.</exception>
		/// <exception cref="ArgumentException">If <paramref name="hashedPassword"/> is too long.</exception>
		public static bool VerifyPassword(
			string hashedPassword,
			ReadOnlySpan<byte> password)
		{
			ArgumentNullException.ThrowIfNull(hashedPassword);

			Span<byte> buffer = stackalloc byte[EncodedLen];
			if (Encoding.ASCII.GetBytes(hashedPassword, buffer) >= EncodedLen)
			{
				throw new ArgumentException($"Hashed password is too long. Max allowed length is {EncodedLen - 1} characters.", nameof(hashedPassword));
			};

			int result = Native.crypto_pwhash_str_verify(
				buffer,
				password, (ulong)password.Length);

			return result == 0;
		}

		/// <summary>
		/// Verifies a password string against a previously hashed string.
		/// </summary>
		/// <param name="hashedPassword">The encoded password hash string (must be ASCII and null-terminated).</param>
		/// <param name="password">The password to verify (as string).</param>
		/// <returns><c>true</c> if the password is valid; otherwise, <c>false</c>.</returns>
		/// <exception cref="ArgumentNullException">If <paramref name="password"/> is null.</exception>
		public static bool VerifyPassword(
			string hashedPassword,
			string password)
		{
			ArgumentNullException.ThrowIfNull(password);

			var passwordUtf8Len = Encoding.UTF8.GetByteCount(password);
			Span<byte> passwordUtf8 = passwordUtf8Len > Constants.MaxStackAlloc ? new byte[passwordUtf8Len] : stackalloc byte[passwordUtf8Len];
			Encoding.UTF8.GetBytes(password, passwordUtf8);
			return VerifyPassword(hashedPassword, passwordUtf8);
		}
	}
}
