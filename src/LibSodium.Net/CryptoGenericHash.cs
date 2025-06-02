using LibSodium.Interop;
using System.Buffers;
using System.Security.Cryptography;

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
		private const int DefaultBufferSize = 8192; // Default buffer size for stream operations


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
			{
				throw new ArgumentException($"Hash length must be between {MinHashLen} and {MaxHashLen} bytes.", nameof(hash));
			}
			if (key.Length != 0 && (key.Length < MinKeyLen || key.Length > MaxKeyLen))
			{
				throw new ArgumentOutOfRangeException($"Key length must be between {MinKeyLen} and {MaxKeyLen} bytes.", nameof(key));
			}
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_generichash(hash, (nuint)hash.Length, message, (ulong)message.Length, key, (nuint)key.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");
		}

		/// <summary>
		/// Computes a generic hash of the specified message.
		/// </summary>
		/// <param name="hash">The buffer where the computed hash will be written. Its length defines the output size.</param>
		/// <param name="message">The input message to hash.</param>
		/// <param name="key">An optional key for keyed hashing (HMAC-like). May be null for unkeyed mode.</param>
		/// <exception cref="ArgumentException">
		/// Thrown if <paramref name="hash"/> has an invalid length, or if <paramref name="key"/> is too long.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the hashing operation fails internally.</exception>

		public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message, SecureMemory<byte>? key = null)
		{
			ComputeHash(hash, message, key == null ? default : key.AsReadOnlySpan());
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
			ArgumentNullException.ThrowIfNull(input, nameof(input));

			using (var incrementalHash = CreateIncrementalHash(key, hash.Length))
			{
				incrementalHash.Compute(input, hash);
			}
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

		public static void ComputeHash(Span<byte> hash, Stream input, SecureMemory<byte>? key = null)
		{
			ComputeHash(hash, input, key == null ? default : key.AsReadOnlySpan());
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
			ArgumentNullException.ThrowIfNull(input, nameof(input));

			using (var incrementalHash = CreateIncrementalHash(key.Span, hash.Length))
			{
				await incrementalHash.ComputeAsync(input, hash, cancellationToken).ConfigureAwait(false);
			}
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

		public static async Task ComputeHashAsync(Memory<byte> hash, Stream input, SecureMemory<byte>? key = null, CancellationToken cancellationToken = default)
		{
			await ComputeHashAsync(hash, input, key == null ? default : key.AsReadOnlyMemory(), cancellationToken).ConfigureAwait(false);
		}

		public static ICryptoIncrementalHash CreateIncrementalHash(ReadOnlySpan<byte> key = default, int hashLen = HashLen)
		{
			return new CryptoGenericHashIncremental(key, hashLen);
		}

		public static ICryptoIncrementalHash CreateIncrementalHash(SecureMemory<byte>? key = null, int hashLen = HashLen)
		{
			return new CryptoGenericHashIncremental(key == null ? default : key.AsReadOnlySpan(), hashLen);
		}

	}
}
