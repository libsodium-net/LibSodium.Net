using System.Buffers;

namespace LibSodium;

/// <summary>
/// Represents an incremental hash or MAC calculator that processes data in chunks and produces a fixed-size output.
/// </summary>
public interface ICryptoIncrementalHash : IDisposable
{
	/// <summary>
	/// Appends data to the ongoing hash or MAC computation.
	/// </summary>
	/// <param name="data">The input data to append. May be empty.</param>
	void Update(ReadOnlySpan<byte> data);

	/// <summary>
	/// Finalizes the hash or MAC computation and writes the result to the specified buffer.
	/// </summary>
	/// <param name="hash">The buffer where the final result will be written. Must match the expected output length.</param>
	/// <exception cref="InvalidOperationException">Thrown if called more than once.</exception>
	void Final(Span<byte> hash);


}

internal static class CryptoIncrementalHashExtensions
{
	/// <summary>
	/// Processes all data from the specified stream and finalizes the hash or MAC computation.
	/// </summary>
	/// <param name="incrementalHash"></param>
	/// <param name="input">The input stream to read and process. Cannot be null.</param>
	/// <param name="hash">The buffer where the final result will be written. Must match the expected output length.</param>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="hash"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the computation fails internally.</exception>
	public static void Compute(this ICryptoIncrementalHash incrementalHash, Stream input, Span<byte> hash)
	{
		ArgumentNullException.ThrowIfNull(input);

		byte[] buffer = ArrayPool<byte>.Shared.Rent(Constants.DefaultBufferLen);
		try
		{
			int read;
			while ((read = input.Read(buffer, 0, Constants.DefaultBufferLen)) > 0)
			{
				incrementalHash.Update(buffer.AsSpan(0, read));
			}
			incrementalHash.Final(hash);
		}
		finally
		{
			SecureMemory.MemZero(buffer);
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	/// <summary>
	/// Asynchronously processes all data from the specified stream and finalizes the hash or MAC computation.
	/// </summary>
	/// <param name="incrementalHash">The incremental hash used to compute the hash over the stream</param>
	/// <param name="input">The input stream to read and process. Cannot be null.</param>
	/// <param name="hash">The memory buffer where the final result will be written. Must match the expected output length.</param>
	/// <param name="cancellationToken">A cancellation token to abort the operation if needed.</param>
	/// <returns>A task that completes when the final result has been written to <paramref name="hash"/>.</returns>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="hash"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the computation fails internally.</exception>
	public static async Task ComputeAsync(this ICryptoIncrementalHash incrementalHash, Stream input, Memory<byte> hash, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(input);

		byte[] buffer = ArrayPool<byte>.Shared.Rent(Constants.DefaultBufferLen);
		try
		{
			int read;
			while ((read = await input.ReadAsync(buffer, 0, Constants.DefaultBufferLen, cancellationToken).ConfigureAwait(false)) > 0)
			{
				incrementalHash.Update(buffer.AsSpan(0, read));
			}
			incrementalHash.Final(hash.Span);
		}
		finally
		{
			SecureMemory.MemZero(buffer);
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

}
