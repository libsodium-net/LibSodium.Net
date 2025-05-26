using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using LibSodium.LowLevel;

namespace LibSodium;

/// <summary>
/// Provides generic one-shot and streaming helpers for key-less hash functions like SHA‑2.
/// </summary>
/// <typeparam name="T">The hash algorithm (e.g., <see cref="Sha256"/>).</typeparam>
internal static class CryptoKeyLessHash<T> where T : IKeyLessHash
{
	/// <summary>
	/// Gets the length of the output hash in bytes.
	/// </summary>
	public static int HashLen => T.HashLen;

	/// <summary>
	/// Gets the size of the internal hashing state structure.
	/// </summary>
	public static int StateLen => T.StateLen;

	/// <summary>
	/// Computes a hash of <paramref name="message"/> and stores the result in <paramref name="hash"/>.
	/// </summary>
	/// <param name="hash">Destination buffer. Must be <see cref="HashLen"/> bytes.</param>
	/// <param name="message">Message to hash.</param>
	public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
	{
		if (hash.Length != HashLen)
			throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));

		LibraryInitializer.EnsureInitialized();
		if (T.ComputeHash(hash, message) != 0)
			throw new LibSodiumException("Hashing failed.");
	}

	/// <summary>
	/// Computes a hash over the contents of a stream.
	/// </summary>
	/// <param name="hash">The buffer that will receive the final hash. Must be <see cref="HashLen"/> bytes.</param>
	/// <param name="input">The input stream to read and hash.</param>
	public static void ComputeHash(Span<byte> hash, Stream input)
	{
		ArgumentNullException.ThrowIfNull(input);
		using var h = CreateIncrementalHash();
		h.Compute(input, hash);
	}

	/// <summary>
	/// Asynchronously computes a hash over the contents of a stream.
	/// </summary>
	/// <param name="hash">The buffer that will receive the final hash. Must be <see cref="HashLen"/> bytes.</param>
	/// <param name="input">The input stream to read and hash.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	public static Task ComputeHashAsync(Memory<byte> hash, Stream input, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(input);
		using var h = CreateIncrementalHash();
		return h.ComputeAsync(input, hash, cancellationToken);
	}

	/// <summary>
	/// Creates an incremental hashing engine for algorithm <typeparamref name="T"/>.
	/// </summary>
	/// <returns>A new <see cref="ICryptoIncrementalHash"/> instance.</returns>
	public static ICryptoIncrementalHash CreateIncrementalHash()
		=> new CryptoKeyLessHashIncremental<T>();
}
