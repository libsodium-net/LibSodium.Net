using LibSodium.Interop;

namespace LibSodium;

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

	/// <summary>
	/// Computes a SHA‑256 hash of <paramref name="message"/> and stores the result in
	/// <paramref name="hash"/>.
	/// </summary>
	/// <param name="hash">Destination buffer (32 bytes).</param>
	/// <param name="message">Message to hash.</param>
	/// <exception cref="ArgumentException">If <paramref name="hash"/> length ≠ 32.</exception>
	/// <exception cref="LibSodiumException">If the native function returns non‑zero.</exception>
	public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
		=> CryptoKeyLessHash<LowLevel.Sha256>.ComputeHash(hash, message);

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
		=> CryptoKeyLessHash<LowLevel.Sha256>.ComputeHash(hash, input);


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
		=> await CryptoKeyLessHash<LowLevel.Sha256>.ComputeHashAsync(hash, input, cancellationToken).ConfigureAwait(false);


	/// <summary>
	/// Creates a new instance of an incremental hash computation object using the SHA-512 algorithm.
	/// </summary>
	/// <remarks>This method provides an object for computing a hash incrementally, which is useful for processing
	/// large data streams or when the data to be hashed is not available all at once.</remarks>
	/// <returns>An <see cref="ICryptoIncrementalHash"/> instance that allows incremental computation of a SHA-512 hash.</returns>
	/// <exception cref="LibSodiumException">Thrown if the underlying libsodium call fails.</exception>
	public static ICryptoIncrementalHash CreateIncrementalHash()
	{
		return new CryptoKeyLessHashIncremental<LowLevel.Sha256>();
	}
}
