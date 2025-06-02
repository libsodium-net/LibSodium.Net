using LibSodium.Interop;
using System.Text;

namespace LibSodium;

/// <summary>
/// Provides password hashing and key derivation using the Scrypt algorithm.
/// </summary>
/// <remarks>
/// Based on libsodium's crypto_pwhash_scryptsalsa208sha256 API: https://doc.libsodium.org/advanced/scrypt
/// </remarks>
public static class CryptoPasswordHashScrypt
{
	/// <summary>
	/// Minimum allowed length in bytes for the derived key (16).
	/// </summary>
	public const int MinKeyLen = Native.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_BYTES_MIN;
	/// <summary>
	/// Minimum allowed password length in bytes (0).
	/// </summary>
	public const int MinPasswordLen = Native.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_PASSWD_MIN;

	/// <summary>
	/// Length of the salt in bytes (32).
	/// </summary>
	public const int SaltLen = Native.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES;


	/// <summary>
	/// Maximum length of the encoded hash string (includes null terminator) (102).
	/// </summary>
	public const int EncodedLen = Native.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES;

	/// <summary>Minimum recommended iterations for dual-phase scenarios (2^10 = 1Ki).</summary>
	public const int MinIterations = 1 << 10;

	/// <summary>Recommended iterations for login or general use (2^19 = 421Mi).</summary>
	public const int InteractiveIterations = 1 << 19;

	/// <summary>Recommended iterations for moderate-strength secrets (2^22 = 4Gi).</summary>
	public const int ModerateIterations = 1 << 22;

	/// <summary>Recommended iterations for high-value secrets (2^25 = 32Gi).</summary>
	public const int SensitiveIterations = 1 << 25;

	/// <summary>Minimum recommended memory usage (2^15 = 32 KiB).</summary>
	public const int MinMemoryLen = 1 << 15;

	/// <summary>Recommended memory usage for interactive scenarios (2^24 = 16 MiB).</summary>
	public const int InteractiveMemoryLen = 1 << 24;

	/// <summary>Recommended memory usage for moderate-strength secrets (2^27 = 128 MiB).</summary>
	public const int ModerateMemoryLen = 1 << 27;

	/// <summary>Recommended memory usage for high-value secrets (2^30 = 1 GiB).</summary>
	public const int SensitiveMemoryLen = 1 << 30;

	/// <summary>Prefix for the encoded hash string (e.g. "$7$").</summary>
	public const string Prefix = Native.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX;

	/// <summary>
	/// Derives a secret key from a password and salt using scrypt.
	/// </summary>
	/// <param name="key">Buffer to receive the derived key (recommended: 32 bytes).</param>
	/// <param name="password">The password to hash.</param>
	/// <param name="salt">The salt (must be 32 bytes).</param>
	/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
	/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
	/// <exception cref="ArgumentException">If arguments are invalid.</exception>
	/// <exception cref="LibSodiumException">If hashing fails.</exception>
	public static void DeriveKey(
		Span<byte> key,
		ReadOnlySpan<byte> password,
		ReadOnlySpan<byte> salt,
		int iterations = InteractiveIterations,
		int requiredMemoryLen = InteractiveMemoryLen)
	{
		if (key.Length < MinKeyLen)
			throw new ArgumentOutOfRangeException(nameof(key), $"Key length must be at least {MinKeyLen} bytes.");
		if (password.Length < MinPasswordLen)
			throw new ArgumentOutOfRangeException(nameof(password), $"Password length must be at least {MinPasswordLen} bytes.");
		if (salt.Length != SaltLen)
			throw new ArgumentException($"Salt must be exactly {SaltLen} bytes.", nameof(salt));
		if (iterations < MinIterations)
			throw new ArgumentOutOfRangeException(nameof(iterations), $"Iterations must be at least {MinIterations}.");
		if (requiredMemoryLen < MinMemoryLen)
			throw new ArgumentOutOfRangeException(nameof(requiredMemoryLen), $"Memory length must be at least {MinMemoryLen} bytes.");

		LibraryInitializer.EnsureInitialized();

		int result = Native.crypto_pwhash_scryptsalsa208sha256(
			key,
			(ulong)key.Length,
			password,
			(ulong)password.Length,
			salt,
			(ulong)iterations,
			(nuint)requiredMemoryLen);

		if (result != 0)
			throw new LibSodiumException("DeriveKey failed. Possible out of memory.");
	}

	/// <summary>
	/// Derives a secret key from a password and salt using scrypt.
	/// </summary>
	/// <param name="key">Buffer to receive the derived key (recommended: 32 bytes).</param>
	/// <param name="password">The password to hash.</param>
	/// <param name="salt">The salt (must be 32 bytes).</param>
	/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
	/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
	/// <exception cref="ArgumentException">If arguments are invalid.</exception>
	/// <exception cref="LibSodiumException">If hashing fails.</exception>
	public static void DeriveKey(
		SecureMemory<byte> key,
		SecureMemory<byte> password,
		ReadOnlySpan<byte> salt,
		int iterations = InteractiveIterations,
		int requiredMemoryLen = InteractiveMemoryLen)
	{
		DeriveKey(
			key.AsSpan(),
			password.AsReadOnlySpan(),
			salt,
			iterations,
			requiredMemoryLen);
	}

	/// <summary>
	/// Derives a secret key from a password string and salt using scrypt.
	/// </summary>
	/// <param name="key">Buffer to receive the derived key (recommended: 32 bytes).</param>
	/// <param name="password">The password string to hash.</param>
	/// <param name="salt">The salt (must be 32 bytes).</param>
	/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
	/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
	/// <exception cref="ArgumentNullException">If the password is null.</exception>
	/// <exception cref="LibSodiumException">If hashing fails.</exception>
	public static void DeriveKey(
		Span<byte> key,
		string password,
		ReadOnlySpan<byte> salt,
		int iterations = InteractiveIterations,
		int requiredMemoryLen = InteractiveMemoryLen)
	{
		ArgumentNullException.ThrowIfNull(password);

		var passwordUtf8Len = Encoding.UTF8.GetByteCount(password);
		Span<byte> passwordUtf8 = passwordUtf8Len > Constants.MaxStackAlloc ? new byte[passwordUtf8Len] : stackalloc byte[passwordUtf8Len];
		Encoding.UTF8.GetBytes(password, passwordUtf8);

		DeriveKey(key, passwordUtf8, salt, iterations, requiredMemoryLen);
	}

	/// <summary>
	/// Derives a secret key from a password string and salt using scrypt.
	/// </summary>
	/// <param name="key">Buffer to receive the derived key (recommended: 32 bytes).</param>
	/// <param name="password">The password string to hash.</param>
	/// <param name="salt">The salt (must be 32 bytes).</param>
	/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
	/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
	/// <exception cref="ArgumentNullException">If the password is null.</exception>
	/// <exception cref="LibSodiumException">If hashing fails.</exception>
	public static void DeriveKey(
		SecureMemory<byte> key,
		string password,
		ReadOnlySpan<byte> salt,
		int iterations = InteractiveIterations,
		int requiredMemoryLen = InteractiveMemoryLen)
	{
		DeriveKey(
			key.AsSpan(),
			password,
			salt,
			iterations,
			requiredMemoryLen);
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
			throw new ArgumentOutOfRangeException(nameof(password), $"Password length must be at least {MinPasswordLen} bytes.");
		if (iterations < MinIterations)
			throw new ArgumentOutOfRangeException(nameof(iterations), $"Iterations must be at least {MinIterations}.");
		if (requiredMemoryLen < MinMemoryLen)
			throw new ArgumentOutOfRangeException(nameof(requiredMemoryLen), $"Memory length must be at least {MinMemoryLen} bytes.");

		Span<byte> buffer = stackalloc byte[EncodedLen];
		int result = Native.crypto_pwhash_scryptsalsa208sha256_str(
			buffer,
			password,
			(ulong)password.Length,
			(ulong)iterations,
			(nuint)requiredMemoryLen);

		if (result != 0)
			throw new LibSodiumException("HashPassword failed. Possible out of memory.");

		return Encoding.ASCII.GetString(buffer.Slice(0, buffer.IndexOf((byte)0)));
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
	SecureMemory<byte> password,
	int iterations = InteractiveIterations,
	int requiredMemoryLen = InteractiveMemoryLen)
	{
		return HashPassword(
			password.AsReadOnlySpan(),
			iterations,
			requiredMemoryLen);
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
			throw new ArgumentException($"Hashed password is too long. Max allowed length is {EncodedLen - 1} characters.", nameof(hashedPassword));

		int result = Native.crypto_pwhash_scryptsalsa208sha256_str_verify(
			buffer,
			password,
			(ulong)password.Length);

		return result == 0;
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
		SecureMemory<byte> password)
	{
		return VerifyPassword(
			hashedPassword,
			password.AsReadOnlySpan());
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
