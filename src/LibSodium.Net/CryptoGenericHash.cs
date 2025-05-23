﻿using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides a high-level interface to the libsodium generic hash function, based on BLAKE2b.
	/// </summary>
	/// <remarks>
	/// This class wraps the <c>crypto_generichash</c> functions from libsodium, offering both one-shot and streaming hash computations.
	/// The output length and key length can be customized within defined bounds. The hash can be computed over a byte span or a stream,
	/// synchronously or asynchronously.
	/// <para>
	/// For additional details, see the official libsodium documentation: 🧂
	/// https://libsodium.gitbook.io/doc/hashing/generic_hashing
	/// </para>
	/// </remarks>
	public static class CryptoGenericHash
	{
		/// <summary>
		/// Default hash length in bytes (32).
		/// </summary>
		public const int HashLen = Native.CRYPTO_GENERICHASH_BYTES;
		/// <summary>
		/// Minimum allowed length in bytes for the hash (16).
		/// </summary>
		public const int MinHashLen = Native.CRYPTO_GENERICHASH_BYTES_MIN;
		/// <summary>
		/// Maximum allowed length in bytes for the hash (64).
		/// </summary>
		public const int MaxHashLen = Native.CRYPTO_GENERICHASH_BYTES_MAX;
		/// <summary>
		/// Default key length in bytes (32).
		/// </summary>
		public const int KeyLen = Native.CRYPTO_GENERICHASH_KEYBYTES;
		/// <summary>
		/// Minimum length in bytes for secret keys (16).
		/// </summary>
		public const int MinKeyLen = Native.CRYPTO_GENERICHASH_KEYBYTES_MIN;
		/// <summary>
		/// Maximum allowed key length in bytes (64 bytes).
		/// </summary>
		public const int MaxKeyLen = Native.CRYPTO_GENERICHASH_KEYBYTES_MAX;

		internal static readonly int StateLen = (int) Native.crypto_generichash_statebytes();

		/// <summary>
		/// Computes a generic hash of the specified message.
		/// </summary>
		/// <param name="hash">The buffer where the computed hash will be written. Its length defines the output size.</param>
		/// <param name="message">The input message to hash.</param>
		/// <param name="key">An optional key for keyed hashing (HMAC-like). May be empty for unkeyed mode.</param>
		/// <exception cref="ArgumentException">
		/// Thrown if <paramref name="hash"/> has an invalid length, or if <paramref name="key"/> is too long.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the hashing operation fails internally.</exception>

		public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key = default)
		{
			if (hash.Length < MinHashLen || hash.Length > MaxHashLen)
				throw new ArgumentException($"Hash length must be between {MinHashLen} and {MaxHashLen} bytes.", nameof(hash));
			if (key.Length > MaxKeyLen)
				throw new ArgumentException($"Key length must be between 0 and {MaxKeyLen} bytes.", nameof(key));
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_generichash(hash, (nuint)hash.Length, message, (ulong)message.Length, key, (nuint)key.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");
		}

		/// <summary>
		/// Computes a generic hash from the contents of a stream.
		/// </summary>
		/// <param name="hash">The buffer where the computed hash will be written. Its length defines the output size.</param>
		/// <param name="input">The input stream to read and hash.</param>
		/// <param name="key">An optional key for keyed hashing (HMAC-like). May be empty for unkeyed mode.</param>
		/// <exception cref="ArgumentException">
		/// Thrown if <paramref name="hash"/> has an invalid length, or if <paramref name="key"/> is too long.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the hashing operation fails internally.</exception>

		public static void ComputeHash(Span<byte> hash, Stream input, ReadOnlySpan<byte> key = default)
		{
			if (hash.Length < MinHashLen || hash.Length > MaxHashLen)
				throw new ArgumentException($"Hash length must be between {MinHashLen} and {MaxHashLen} bytes.", nameof(hash));
			if (key.Length > MaxKeyLen)
				throw new ArgumentException($"Key length must be between 0 and {MaxKeyLen} bytes.", nameof(key));
			Span<byte> state = stackalloc byte[StateLen];
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_generichash_init(state, key, (nuint)key.Length, (nuint)hash.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");
			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
			{
				result = Native.crypto_generichash_update(state, buffer, (ulong)bytesRead);
				if (result != 0)
					throw new LibSodiumException("Hashing failed.");
			}
			result = Native.crypto_generichash_final(state, hash, (nuint)hash.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");

		}

		/// <summary>
		/// Asynchronously computes a generic hash from the contents of a stream.
		/// </summary>
		/// <param name="hash">The memory buffer where the computed hash will be written. Its length defines the output size.</param>
		/// <param name="input">The input stream to read and hash.</param>
		/// <param name="key">An optional key for keyed hashing (HMAC-like). May be empty for unkeyed mode.</param>
		/// <param name="cancellationToken">A cancellation token to cancel the operation.</param>
		/// <returns>A task representing the asynchronous hash computation.</returns>
		/// <exception cref="ArgumentException">
		/// Thrown if <paramref name="hash"/> has an invalid length, or if <paramref name="key"/> is too long.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the hashing operation fails internally.</exception>

		public static async Task ComputeHashAsync(Memory<byte> hash, Stream input, ReadOnlyMemory<byte> key = default, CancellationToken cancellationToken = default)
		{
			if (hash.Length < MinHashLen || hash.Length > MaxHashLen)
				throw new ArgumentException($"Hash length must be between {MinHashLen} and {MaxHashLen} bytes.", nameof(hash));
			if (key.Length > MaxKeyLen)
				throw new ArgumentException($"Key length must be between 0 and {MaxKeyLen} bytes.", nameof(key));

			byte[] stateBuffer = new byte[StateLen];
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_generichash_init(stateBuffer, key.Span, (nuint)key.Length, (nuint)hash.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");

			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
			{
				result = Native.crypto_generichash_update(stateBuffer, buffer, (ulong) bytesRead);
				if (result != 0)
					throw new LibSodiumException("Hashing failed.");
			}

			result = Native.crypto_generichash_final(stateBuffer, hash.Span, (nuint)hash.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");
		}

	}
}
