using LibSodium.LowLevel;

namespace LibSodium;

/// <summary>
/// Incremental hashing engine for algorithms that do not require a key (e.g., SHA‑2).
/// </summary>
/// <typeparam name="T">The underlying hash algorithm.</typeparam>
internal sealed class CryptoKeyLessHashIncremental<T> : ICryptoIncrementalOperation
	where T : IKeyLessHash
{
	private readonly byte[] state = new byte[T.StateLen];
	private bool isFinalized = false;
	private bool isDisposed = false;

	/// <summary>
	/// Initializes a new incremental hash instance for algorithm <typeparamref name="T"/>.
	/// </summary>
	public CryptoKeyLessHashIncremental()
	{
		if (T.Init(state) != 0)
			throw new LibSodiumException("Failed to initialize the incremental hashing operation.");
	}

	private void CheckDisposed()
	{
		if (isDisposed)
			throw new ObjectDisposedException(nameof(CryptoKeyLessHashIncremental<T>), "The incremental hashing instance has already been disposed.");
	}

	/// <summary>
	/// Appends data to the ongoing hash computation.
	/// </summary>
	/// <param name="data">The input data to append.</param>
	/// <exception cref="ObjectDisposedException">If the instance has been disposed.</exception>
	/// <exception cref="InvalidOperationException">If <see cref="Final"/> has already been called.</exception>
	public void Update(ReadOnlySpan<byte> data)
	{
		CheckDisposed();
		if (isFinalized)
			throw new InvalidOperationException("Cannot update after the incremental hashing operation has been finalized.");

		if (T.Update(state, data) != 0)
			throw new LibSodiumException("Failed to update the hash state.");
	}

	/// <summary>
	/// Finalizes the hash computation and writes the result to the specified buffer.
	/// </summary>
	/// <param name="hash">The buffer to receive the final hash. Must be exactly <c>T.HashLen</c> bytes.</param>
	/// <exception cref="ObjectDisposedException">If the instance has been disposed.</exception>
	/// <exception cref="InvalidOperationException">If called more than once.</exception>
	/// <exception cref="ArgumentException">If the buffer length is invalid.</exception>
	public void Final(Span<byte> hash)
	{
		CheckDisposed();
		if (isFinalized)
			throw new InvalidOperationException("Hash has already been finalized.");

		if (hash.Length != T.HashLen)
			throw new ArgumentException($"Hash must be exactly {T.HashLen} bytes.", nameof(hash));

		if (T.Final(state, hash) != 0)
			throw new LibSodiumException("Failed to finalize the hash computation.");

		isFinalized = true;
		SecureMemory.MemZero(state);
	}

	/// <summary>
	/// Disposes the hash state, zeroing it if not already finalized.
	/// </summary>
	public void Dispose()
	{
		if (isDisposed) return;
		isDisposed = true;

		if (!isFinalized)
			SecureMemory.MemZero(state);
	}
}
