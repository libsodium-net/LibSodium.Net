using LibSodium.LowLevel;

namespace LibSodium;

/// <summary>
/// Computes and verifies HMAC-SHA-512/256 message authentication codes.
/// </summary>
public static class CryptoHmacSha512_256
{
	/// <summary>
	/// Length of the HMAC output in bytes (32).
	/// </summary>
	public static readonly int MacLen = HmacSha512_256.MacLen;

	/// <summary>
	/// Length of the secret key in bytes (32).
	/// </summary>
	public static readonly int KeyLen = HmacSha512_256.KeyLen;

	/// <summary>
	/// Computes an HMAC-SHA-512/256 authentication code for the given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to authenticate.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <returns>The length of the MAC written (always 32).</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static int ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
		=> CryptoMac<HmacSha512_256>.ComputeMac(key, message, mac);

	/// <summary>
	/// Computes an HMAC-SHA-512/256 authentication code for the given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to authenticate.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <returns>The length of the MAC written (always 32).</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static int ComputeMac(SecureMemory<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
		=> CryptoMac<HmacSha512_256>.ComputeMac(key.AsReadOnlySpan(), message, mac);


	/// <summary>
	/// Verifies an HMAC-SHA-512/256 authentication code against a given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to verify.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha512_256>.VerifyMac(key, message, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-512/256 authentication code against a given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to verify.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(SecureMemory<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha512_256>.VerifyMac(key.AsReadOnlySpan(), message, mac);

	/// <summary>
	/// Generates a random 32-byte key suitable for HMAC-SHA-512/256.
	/// </summary>
	/// <param name="key">A buffer to receive the generated key (must be 32 bytes).</param>
	public static void GenerateKey(Span<byte> key)
		=> CryptoMac<HmacSha512_256>.GenerateKey(key);

	/// <summary>
	/// Generates a random 32-byte key suitable for HMAC-SHA-512/256.
	/// </summary>
	/// <param name="key">A buffer to receive the generated key (must be 32 bytes).</param>
	public static void GenerateKey(SecureMemory<byte> key)
		=> CryptoMac<HmacSha512_256>.GenerateKey(key.AsSpan());

	/// <summary>
	/// Computes an HMAC-SHA-512/256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static void ComputeMac(ReadOnlySpan<byte> key, Stream messageStream, Span<byte> mac)
		=> CryptoMac<HmacSha512_256>.ComputeMac(key, messageStream, mac);

	/// <summary>
	/// Computes an HMAC-SHA-512/256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static void ComputeMac(SecureMemory<byte> key, Stream messageStream, Span<byte> mac)
		=> CryptoMac<HmacSha512_256>.ComputeMac(key.AsReadOnlySpan(), messageStream, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-512/256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(ReadOnlySpan<byte> key, Stream messageStream, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha512_256>.VerifyMac(key, messageStream, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-512/256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(SecureMemory<byte> key, Stream messageStream, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha512_256>.VerifyMac(key.AsReadOnlySpan(), messageStream, mac);

	/// <summary>
	/// Asynchronously computes an HMAC-SHA-512/256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static Task ComputeMacAsync(ReadOnlyMemory<byte> key, Stream messageStream, Memory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha512_256>.ComputeMacAsync(key, messageStream, mac, cancellationToken);

	/// <summary>
	/// Asynchronously computes an HMAC-SHA-512/256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static Task ComputeMacAsync(SecureMemory<byte> key, Stream messageStream, Memory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha512_256>.ComputeMacAsync(key.AsReadOnlyMemory(), messageStream, mac, cancellationToken);


	/// <summary>
	/// Asynchronously verifies an HMAC-SHA-512/256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static Task<bool> VerifyMacAsync(ReadOnlyMemory<byte> key, Stream messageStream, ReadOnlyMemory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha512_256>.VerifyMacAsync(key, messageStream, mac, cancellationToken);

	/// <summary>
	/// Asynchronously verifies an HMAC-SHA-512/256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static Task<bool> VerifyMacAsync(SecureMemory<byte> key, Stream messageStream, ReadOnlyMemory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha512_256>.VerifyMacAsync(key.AsReadOnlyMemory(), messageStream, mac, cancellationToken);

	/// <summary>
	/// Creates an incremental hash object using the HMAC-SHA512/256 algorithm.
	/// </summary>
	/// <remarks>The returned <see cref="ICryptoIncrementalHash"/> can be used to compute the HMAC-SHA512/256 hash
	/// incrementally by processing data in chunks.</remarks>
	/// <param name="key">The cryptographic key (64 bytes) to use for the HMAC-SHA512/256 computation.</param>
	/// <returns>An <see cref="ICryptoIncrementalHash"/> instance that allows incremental computation of the HMAC-SHA512/256 hash.</returns>
	public static ICryptoIncrementalHash CreateIncrementalMac(ReadOnlySpan<byte> key)
	{
		return new CryptoMacIncremental<HmacSha512_256>(key);
	}

	/// <summary>
	/// Creates an incremental hash object using the HMAC-SHA512/256 algorithm.
	/// </summary>
	/// <remarks>The returned <see cref="ICryptoIncrementalHash"/> can be used to compute the HMAC-SHA512/256 hash
	/// incrementally by processing data in chunks.</remarks>
	/// <param name="key">The cryptographic key (64 bytes) to use for the HMAC-SHA512/256 computation.</param>
	/// <returns>An <see cref="ICryptoIncrementalHash"/> instance that allows incremental computation of the HMAC-SHA512/256 hash.</returns>
	public static ICryptoIncrementalHash CreateIncrementalMac(SecureMemory<byte> key)
	{
		return new CryptoMacIncremental<HmacSha512_256>(key.AsReadOnlySpan());
	}

}
