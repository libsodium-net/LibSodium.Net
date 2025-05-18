using LibSodium.Interop;
using System.Buffers;

namespace LibSodium
{
	/// <summary>
	/// Provides one‑shot and streaming <b>SHA‑256</b> hashing helpers built on libsodium’s
	/// <c>crypto_hash_sha256</c> API.
	/// </summary>
	public static class CryptoSha256
	{
		/// <summary>Hash length in bytes (32).</summary>
		public const int HashLen = Native.CRYPTO_HASH_SHA256_BYTES;

		/// <summary>Size of the internal hashing state structure (implementation‑defined).</summary>
		internal static readonly int StateLen = (int)Native.crypto_hash_sha256_statebytes();

		private const int DefaultBufferSize = 8 * 1024; // 8 KiB


		/// <summary>
		/// Computes a SHA‑256 hash of <paramref name="message"/> and stores the result in
		/// <paramref name="hash"/>.
		/// </summary>
		/// <param name="hash">Destination buffer (32 bytes).</param>
		/// <param name="message">Message to hash.</param>
		/// <exception cref="ArgumentException">If <paramref name="hash"/> length ≠ 32.</exception>
		/// <exception cref="LibSodiumException">If the native function returns non‑zero.</exception>
		public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
		{
			if (hash.Length != HashLen)
				throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_hash_sha256(hash, message, (ulong)message.Length);
			if (rc != 0)
				throw new LibSodiumException("SHA‑256 hashing failed.");
		}

		/// <summary>
		/// Computes a SHA‑256 hash over the entire contents of the supplied <see cref="Stream"/>.
		/// </summary>
		/// <param name="hash">Destination buffer (32 bytes) that receives the final hash.</param>
		/// <param name="input">The input stream to read and hash. The stream is read until its end.</param>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is <c>null</c>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="hash"/> is not exactly 32 bytes.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying libsodium call fails.</exception>
		/// <remarks>
		/// The method processes the stream in buffered chunks of <c>8 KiB</c>, keeping memory usage low even for very large inputs.
		/// </remarks>
		public static void ComputeHash(Span<byte> hash, Stream input)
		{
			ArgumentNullException.ThrowIfNull(input);
			if (hash.Length != HashLen)
				throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));

			Span<byte> state = stackalloc byte[StateLen];
			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_hash_sha256_init(state) != 0)
				throw new LibSodiumException("SHA‑256 init failed.");

			byte[] buffer = ArrayPool<byte>.Shared.Rent(DefaultBufferSize);
			try
			{
				int read;
				while ((read = input.Read(buffer, 0, DefaultBufferSize)) > 0)
				{
					if (Native.crypto_hash_sha256_update(state, buffer, (ulong)read) != 0)
						throw new LibSodiumException("SHA‑256 update failed.");
				}
				if (Native.crypto_hash_sha256_final(state, hash) != 0)
					throw new LibSodiumException("SHA‑256 final failed.");
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
			}
		}

		/// <summary>
		/// Asynchronously computes a SHA‑256 hash over the supplied <see cref="Stream"/>, writing the
		/// result into <paramref name="hash"/>.
		/// </summary>
		/// <param name="hash">Destination memory buffer (32 bytes) that receives the final hash.</param>
		/// <param name="input">The input stream to read and hash. The stream is read until its end.</param>
		/// <param name="cancellationToken">Token that can be used to cancel the asynchronous operation.</param>
		/// <returns>A task that completes when the hash has been fully computed and written.</returns>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is <c>null</c>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="hash"/> is not exactly 32 bytes.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying libsodium call fails.</exception>
		/// <remarks>
		/// The method reads the stream in buffered chunks of <c>8 KiB</c> and is fully asynchronous, making it suitable for
		/// hashing network streams or large files without blocking the calling thread.
		/// </remarks>
		public static async Task ComputeHashAsync(Memory<byte> hash, Stream input, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(input);
			if (hash.Length != HashLen)
				throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));

			byte[] state = new byte[StateLen];
			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_hash_sha256_init(state) != 0)
				throw new LibSodiumException("SHA‑256 init failed.");

			byte[] buffer = ArrayPool<byte>.Shared.Rent(DefaultBufferSize);
			try
			{
				int read;
				while ((read = await input.ReadAsync(buffer, 0, DefaultBufferSize, cancellationToken).ConfigureAwait(false)) > 0)
				{
					if (Native.crypto_hash_sha256_update(state, buffer, (ulong)read) != 0)
						throw new LibSodiumException("SHA‑256 update failed.");
				}
				if (Native.crypto_hash_sha256_final(state, hash.Span) != 0)
					throw new LibSodiumException("SHA‑256 final failed.");
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
			}
		}
	}
}
