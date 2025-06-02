using System.IO;
using System.Threading;
using System.Threading.Tasks;
using LibSodium.LowLevel;

namespace LibSodium;

/// <summary>
/// Computes and verifies Poly1305 one-time authentication codes.
/// </summary>
/// <remarks>
/// Based on libsodium's crypto_onetimeauth API:
/// https://doc.libsodium.org/advanced/poly1305
/// </remarks>
public static class CryptoOneTimeAuth
{
	/// <summary>
	/// Length of the MAC output in bytes (16).
	/// </summary>
	public static readonly int MacLen = LowLevel.CryptoOneTimeAuth.MacLen;

	/// <summary>
	/// Length of the secret key in bytes (32).
	/// </summary>
	public static readonly int KeyLen = LowLevel.CryptoOneTimeAuth.KeyLen;

	/// <summary>
	/// Computes a Poly1305 authentication tag for the given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to authenticate.</param>
	/// <param name="mac">A buffer to receive the 16-byte MAC.</param>
	/// <returns>The number of bytes written to <paramref name="mac"/> (always 16).</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static int ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.ComputeMac(key, message, mac);

	/// <summary>
	/// Computes a Poly1305 authentication tag for the given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to authenticate.</param>
	/// <param name="mac">A buffer to receive the 16-byte MAC.</param>
	/// <returns>The number of bytes written to <paramref name="mac"/> (always 16).</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static int ComputeMac(SecureMemory<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.ComputeMac(key.AsReadOnlySpan(), message, mac);

	/// <summary>
	/// Verifies a Poly1305 authentication tag against a given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to verify.</param>
	/// <param name="mac">The expected 16-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mac)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.VerifyMac(key, message, mac);

	/// <summary>
	/// Verifies a Poly1305 authentication tag against a given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to verify.</param>
	/// <param name="mac">The expected 16-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(SecureMemory<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mac)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.VerifyMac(key.AsReadOnlySpan(), message, mac);

	/// <summary>
	/// Generates a random 32-byte key suitable for Poly1305.
	/// </summary>
	/// <param name="key">A buffer to receive the generated key (must be 32 bytes).</param>
	public static void GenerateKey(Span<byte> key)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.GenerateKey(key);

	/// <summary>
	/// Generates a random 32-byte key suitable for Poly1305.
	/// </summary>
	/// <param name="key">A buffer to receive the generated key (must be 32 bytes).</param>
	public static void GenerateKey(SecureMemory<byte> key)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.GenerateKey(key.AsSpan());

	/// <summary>
	/// Computes a Poly1305 authentication tag from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 16-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static void ComputeMac(ReadOnlySpan<byte> key, Stream messageStream, Span<byte> mac)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.ComputeMac(key, messageStream, mac);

	/// <summary>
	/// Computes a Poly1305 authentication tag from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 16-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static void ComputeMac(SecureMemory<byte> key, Stream messageStream, Span<byte> mac)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.ComputeMac(key.AsReadOnlySpan(), messageStream, mac);

	/// <summary>
	/// Verifies a Poly1305 authentication tag from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 16-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(ReadOnlySpan<byte> key, Stream messageStream, ReadOnlySpan<byte> mac)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.VerifyMac(key, messageStream, mac);

	/// <summary>
	/// Verifies a Poly1305 authentication tag from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 16-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(SecureMemory<byte> key, Stream messageStream, ReadOnlySpan<byte> mac)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.VerifyMac(key.AsReadOnlySpan(), messageStream, mac);

	/// <summary>
	/// Asynchronously computes a Poly1305 authentication tag from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 16-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static Task ComputeMacAsync(ReadOnlyMemory<byte> key, Stream messageStream, Memory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.ComputeMacAsync(key, messageStream, mac, cancellationToken);

	/// <summary>
	/// Asynchronously computes a Poly1305 authentication tag from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 16-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static Task ComputeMacAsync(SecureMemory<byte> key, Stream messageStream, Memory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.ComputeMacAsync(key.AsReadOnlyMemory(), messageStream, mac, cancellationToken);

	/// <summary>
	/// Asynchronously verifies a Poly1305 authentication tag from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 16-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	public static Task<bool> VerifyMacAsync(ReadOnlyMemory<byte> key, Stream messageStream, ReadOnlyMemory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.VerifyMacAsync(key, messageStream, mac, cancellationToken);

	/// <summary>
	/// Asynchronously verifies a Poly1305 authentication tag from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 16-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	public static Task<bool> VerifyMacAsync(SecureMemory<byte> key, Stream messageStream, ReadOnlyMemory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<LowLevel.CryptoOneTimeAuth>.VerifyMacAsync(key.AsReadOnlyMemory(), messageStream, mac, cancellationToken);


	/// <summary>
	/// Creates an incremental hash object using the Poly1305 algorithm.
	/// </summary>
	/// <remarks>The returned <see cref="ICryptoIncrementalHash"/> can be used to compute the Poly1305 hash
	/// incrementally by processing data in chunks.</remarks>
	/// <param name="key">The cryptographic key (32 bytes) to use for the Poly1305 computation.</param>
	/// <returns>An <see cref="ICryptoIncrementalHash"/> instance that allows incremental computation of the Poly1305 hash.</returns>
	public static ICryptoIncrementalHash CreateIncrementalMac(ReadOnlySpan<byte> key)
	{
		return new CryptoMacIncremental<LowLevel.CryptoOneTimeAuth>(key);
	}

	/// <summary>
	/// Creates an incremental hash object using the Poly1305 algorithm.
	/// </summary>
	/// <remarks>The returned <see cref="ICryptoIncrementalHash"/> can be used to compute the Poly1305 hash
	/// incrementally by processing data in chunks.</remarks>
	/// <param name="key">The cryptographic key (32 bytes) to use for the Poly1305 computation.</param>
	/// <returns>An <see cref="ICryptoIncrementalHash"/> instance that allows incremental computation of the Poly1305 hash.</returns>
	public static ICryptoIncrementalHash CreateIncrementalMac(SecureMemory<byte> key)
	{
		return new CryptoMacIncremental<LowLevel.CryptoOneTimeAuth>(key.AsReadOnlySpan());
	}
}
