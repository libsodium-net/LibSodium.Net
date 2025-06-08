using System.Buffers;

namespace LibSodium;

/// <summary>
/// Represents an incremental operation such as incremental hash, MAC, or sign calculation that processes data in chunks and produces a fixed-size output.
/// </summary>
public interface ICryptoIncrementalOperation : IDisposable
{
	/// <summary>
	/// Appends data to the ongoing hash or MAC computation.
	/// </summary>
	/// <param name="data">The input data to append. May be empty.</param>
	void Update(ReadOnlySpan<byte> data);

	/// <summary>
	/// Finalizes the incremental computation and writes the result to the specified buffer.
	/// </summary>
	/// <param name="result">The buffer where the final result will be written. Must match the expected output length.</param>
	/// <exception cref="InvalidOperationException">Thrown if called more than once.</exception>
	void Final(Span<byte> result);


}

internal static class CryptoIncrementalOperationExtensions
{
	/// <summary>
	/// Processes all data from the specified stream and finalizes the hash or MAC computation.
	/// </summary>
	/// <param name="incrementalOperation"></param>
	/// <param name="input">The input stream to read and process. Cannot be null.</param>
	/// <param name="result">The buffer where the final result will be written. Must match the expected output length.</param>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="result"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the computation fails internally.</exception>
	public static void Compute(this ICryptoIncrementalOperation incrementalOperation, Stream input, Span<byte> result)
	{
		ArgumentNullException.ThrowIfNull(input);

		byte[] buffer = ArrayPool<byte>.Shared.Rent(Constants.DefaultBufferLen);
		try
		{
			int read;
			while ((read = input.Read(buffer, 0, Constants.DefaultBufferLen)) > 0)
			{
				incrementalOperation.Update(buffer.AsSpan(0, read));
			}
			incrementalOperation.Final(result);
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
	/// <param name="incrementalOperation">The incremental hash used to compute the hash over the stream</param>
	/// <param name="input">The input stream to read and process. Cannot be null.</param>
	/// <param name="result">The memory buffer where the final result will be written. Must match the expected output length.</param>
	/// <param name="cancellationToken">A cancellation token to abort the operation if needed.</param>
	/// <returns>A task that completes when the final result has been written to <paramref name="result"/>.</returns>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="result"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the computation fails internally.</exception>
	public static async Task ComputeAsync(this ICryptoIncrementalOperation incrementalOperation, Stream input, Memory<byte> result, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(input);

		byte[] buffer = ArrayPool<byte>.Shared.Rent(Constants.DefaultBufferLen);
		try
		{
			int read;
			while ((read = await input.ReadAsync(buffer, 0, Constants.DefaultBufferLen, cancellationToken).ConfigureAwait(false)) > 0)
			{
				incrementalOperation.Update(buffer.AsSpan(0, read));
			}
			incrementalOperation.Final(result.Span);
		}
		finally
		{
			SecureMemory.MemZero(buffer);
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}
}
