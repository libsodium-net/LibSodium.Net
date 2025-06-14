﻿using LibSodium.LowLevel;

namespace LibSodium;

/// <summary>
/// Computes and verifies HMAC-SHA-512 message authentication codes.
/// </summary>
public static class CryptoHmacSha512
{
	/// <summary>
	/// Length of the HMAC output in bytes (64).
	/// </summary>
	public static readonly int MacLen = HmacSha512.MacLen;

	/// <summary>
	/// Length of the secret key in bytes (32).
	/// </summary>
	public static readonly int KeyLen = HmacSha512.KeyLen;

	/// <summary>
	/// Computes an HMAC-SHA-512 authentication code for the given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to authenticate.</param>
	/// <param name="mac">A buffer to receive the 64-byte MAC.</param>
	/// <returns>The length of the MAC written (always 64).</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static int ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
		=> CryptoMac<HmacSha512>.ComputeMac(key, message, mac);

	/// <summary>
	/// Computes an HMAC-SHA-512 authentication code for the given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to authenticate.</param>
	/// <param name="mac">A buffer to receive the 64-byte MAC.</param>
	/// <returns>The length of the MAC written (always 64).</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static int ComputeMac(SecureMemory<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
		=> CryptoMac<HmacSha512>.ComputeMac(key.AsReadOnlySpan(), message, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-512 authentication code against a given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to verify.</param>
	/// <param name="mac">The expected 64-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha512>.VerifyMac(key, message, mac);


	/// <summary>
	/// Verifies an HMAC-SHA-512 authentication code against a given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to verify.</param>
	/// <param name="mac">The expected 64-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(SecureMemory<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha512>.VerifyMac(key.AsReadOnlySpan(), message, mac);

	/// <summary>
	/// Generates a random 32-byte key suitable for HMAC-SHA-512.
	/// </summary>
	/// <param name="key">A buffer to receive the generated key (must be 32 bytes).</param>
	public static void GenerateKey(Span<byte> key)
		=> CryptoMac<HmacSha512>.GenerateKey(key);

	/// <summary>
	/// Generates a random 32-byte key suitable for HMAC-SHA-512.
	/// </summary>
	/// <param name="key">A buffer to receive the generated key (must be 32 bytes).</param>
	public static void GenerateKey(SecureMemory<byte> key)
		=> CryptoMac<HmacSha512>.GenerateKey(key.AsSpan());

	/// <summary>
	/// Computes an HMAC-SHA-512 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 64-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static void ComputeMac(ReadOnlySpan<byte> key, Stream messageStream, Span<byte> mac)
		=> CryptoMac<HmacSha512>.ComputeMac(key, messageStream, mac);

	/// <summary>
	/// Computes an HMAC-SHA-512 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 64-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static void ComputeMac(SecureMemory<byte> key, Stream messageStream, Span<byte> mac)
		=> CryptoMac<HmacSha512>.ComputeMac(key.AsReadOnlySpan(), messageStream, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-512 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 64-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(SecureMemory<byte> key, Stream messageStream, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha512>.VerifyMac(key.AsReadOnlySpan(), messageStream, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-512 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 64-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(ReadOnlySpan<byte> key, Stream messageStream, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha512>.VerifyMac(key, messageStream, mac);


	/// <summary>
	/// Asynchronously computes an HMAC-SHA-512 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 64-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static Task ComputeMacAsync(ReadOnlyMemory<byte> key, Stream messageStream, Memory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha512>.ComputeMacAsync(key, messageStream, mac, cancellationToken);


	/// <summary>
	/// Asynchronously computes an HMAC-SHA-512 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 64-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static Task ComputeMacAsync(SecureMemory<byte> key, Stream messageStream, Memory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha512>.ComputeMacAsync(key.AsReadOnlyMemory(), messageStream, mac, cancellationToken);


	/// <summary>
	/// Asynchronously verifies an HMAC-SHA-512 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 64-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static Task<bool> VerifyMacAsync(ReadOnlyMemory<byte> key, Stream messageStream, ReadOnlyMemory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha512>.VerifyMacAsync(key, messageStream, mac, cancellationToken);



	/// <summary>
	/// Asynchronously verifies an HMAC-SHA-512 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 64-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static Task<bool> VerifyMacAsync(SecureMemory<byte> key, Stream messageStream, ReadOnlyMemory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha512>.VerifyMacAsync(key.AsReadOnlyMemory(), messageStream, mac, cancellationToken);


	/// <summary>
	/// Creates an incremental hash object using the HMAC-SHA512 algorithm.
	/// </summary>
	/// <remarks>The returned <see cref="ICryptoIncrementalOperation"/> can be used to compute the HMAC-SHA512 hash
	/// incrementally by processing data in chunks.</remarks>
	/// <param name="key">The cryptographic key (64 bytes) to use for the HMAC-SHA512 computation.</param>
	/// <returns>An <see cref="ICryptoIncrementalOperation"/> instance that allows incremental computation of the HMAC-SHA512 hash.</returns>
	public static ICryptoIncrementalOperation CreateIncrementalMac(ReadOnlySpan<byte> key)
	{
		return new CryptoMacIncremental<HmacSha512>(key);
	}

	/// <summary>
	/// Creates an incremental hash object using the HMAC-SHA512 algorithm.
	/// </summary>
	/// <remarks>The returned <see cref="ICryptoIncrementalOperation"/> can be used to compute the HMAC-SHA512 hash
	/// incrementally by processing data in chunks.</remarks>
	/// <param name="key">The cryptographic key (64 bytes) to use for the HMAC-SHA512 computation.</param>
	/// <returns>An <see cref="ICryptoIncrementalOperation"/> instance that allows incremental computation of the HMAC-SHA512 hash.</returns>
	public static ICryptoIncrementalOperation CreateIncrementalMac(SecureMemory<byte> key)
	{
		return new CryptoMacIncremental<HmacSha512>(key.AsReadOnlySpan());
	}

}
