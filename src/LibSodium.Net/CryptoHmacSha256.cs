using System.IO;
using System.Reflection.Metadata.Ecma335;
using System.Threading;
using System.Threading.Tasks;
using LibSodium.LowLevel;

namespace LibSodium;

/// <summary>
/// Computes and verifies HMAC-SHA-256 message authentication codes.
/// </summary>
public static class CryptoHmacSha256
{
	/// <summary>
	/// Length of the HMAC output in bytes (32).
	/// </summary>
	public static readonly int MacLen = HmacSha256.MacLen;

	/// <summary>
	/// Length of the secret key in bytes (32).
	/// </summary>
	public static readonly int KeyLen = HmacSha256.KeyLen;

	/// <summary>
	/// Computes an HMAC-SHA-256 authentication code for the given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to authenticate.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <returns>The length of the MAC written (always 32).</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static int ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
		=> CryptoMac<HmacSha256>.ComputeMac(key, message, mac);


	/// <summary>
	/// Computes an HMAC-SHA-256 authentication code for the given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to authenticate.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <returns>The length of the MAC written (always 32).</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static int ComputeMac(SecureMemory<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
		=> ComputeMac(key.AsReadOnlySpan(), message, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-256 authentication code against a given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to verify.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha256>.VerifyMac(key, message, mac);


	/// <summary>
	/// Verifies an HMAC-SHA-256 authentication code against a given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to verify.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(SecureMemory<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mac)
		=> VerifyMac(key.AsReadOnlySpan(), message, mac);

	/// <summary>
	/// Generates a random 32-byte key suitable for HMAC-SHA-256.
	/// </summary>
	/// <param name="key">A buffer to receive the generated key (must be 32 bytes).</param>
	public static void GenerateKey(Span<byte> key)
		=> CryptoMac<HmacSha256>.GenerateKey(key);

	/// <summary>
	/// Generates a random 32-byte key suitable for HMAC-SHA-256.
	/// </summary>
	/// <param name="key">A buffer to receive the generated key (must be 32 bytes).</param>
	public static void GenerateKey(SecureMemory<byte> key)
		=> GenerateKey(key.AsSpan());

	/// <summary>
	/// Computes an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static void ComputeMac(ReadOnlySpan<byte> key, Stream messageStream, Span<byte> mac)
		=> CryptoMac<HmacSha256>.ComputeMac(key, messageStream, mac);


	/// <summary>
	/// Computes an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static void ComputeMac(SecureMemory<byte> key, Stream messageStream, Span<byte> mac)
		=> ComputeMac(key.AsReadOnlySpan(), messageStream, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	public static bool VerifyMac(ReadOnlySpan<byte> key, Stream messageStream, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha256>.VerifyMac(key, messageStream, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	public static bool VerifyMac(SecureMemory<byte> key, Stream messageStream, ReadOnlySpan<byte> mac)
		=> VerifyMac(key.AsReadOnlySpan(), messageStream, mac);

	/// <summary>
	/// Asynchronously computes an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static Task ComputeMacAsync(ReadOnlyMemory<byte> key, Stream messageStream, Memory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha256>.ComputeMacAsync(key, messageStream, mac, cancellationToken);

	/// <summary>
	/// Asynchronously computes an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static Task ComputeMacAsync(SecureMemory<byte> key, Stream messageStream, Memory<byte> mac, CancellationToken cancellationToken = default)
		=> ComputeMacAsync(key.AsReadOnlyMemory(), messageStream, mac, cancellationToken);


	/// <summary>
	/// Asynchronously verifies an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	public static async Task<bool> VerifyMacAsync(ReadOnlyMemory<byte> key, Stream messageStream, ReadOnlyMemory<byte> mac, CancellationToken cancellationToken = default)
		=> await CryptoMac<HmacSha256>.VerifyMacAsync(key, messageStream, mac, cancellationToken);


	/// <summary>
	/// Asynchronously verifies an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	public static async Task<bool> VerifyMacAsync(SecureMemory<byte> key, Stream messageStream, ReadOnlyMemory<byte> mac, CancellationToken cancellationToken = default)
		=> await VerifyMacAsync(key.AsReadOnlyMemory(), messageStream, mac, cancellationToken);


	/// <summary>
	/// Creates an incremental hash object using the HMAC-SHA256 algorithm.
	/// </summary>
	/// <remarks>The returned <see cref="ICryptoIncrementalOperation"/> can be used to compute the HMAC-SHA256 hash
	/// incrementally by processing data in chunks. This is useful for scenarios where the data to be hashed is too large
	/// to fit in memory or is received in a streaming fashion.</remarks>
	/// <param name="key">The cryptographic key (32 bytes) to use for the HMAC-SHA256 computation.</param>
	/// <returns>An <see cref="ICryptoIncrementalOperation"/> instance that allows incremental computation of the HMAC-SHA256 hash.</returns>
	public static ICryptoIncrementalOperation CreateIncrementalMac(ReadOnlySpan<byte> key)
	{
		return new CryptoMacIncremental<HmacSha256>(key);
	}

	/// <summary>
	/// Creates an incremental hash object using the HMAC-SHA256 algorithm.
	/// </summary>
	/// <remarks>The returned <see cref="ICryptoIncrementalOperation"/> can be used to compute the HMAC-SHA256 hash
	/// incrementally by processing data in chunks. This is useful for scenarios where the data to be hashed is too large
	/// to fit in memory or is received in a streaming fashion.</remarks>
	/// <param name="key">The cryptographic key (32 bytes) to use for the HMAC-SHA256 computation.</param>
	/// <returns>An <see cref="ICryptoIncrementalOperation"/> instance that allows incremental computation of the HMAC-SHA256 hash.</returns>
	public static ICryptoIncrementalOperation CreateIncrementalMac(SecureMemory<byte> key)
	{
		return CreateIncrementalMac(key.AsReadOnlySpan());
	}
}
