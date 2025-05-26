namespace LibSodium.LowLevel;

/// <summary>
/// Defines a unified interface for hash functions like SHA-2.
/// Supports one-shot and incremental hashing.
/// </summary>
internal interface IKeyLessHash
{
	/// <summary>
	/// Length of the hash output in bytes.
	/// </summary>
	static abstract int HashLen { get; }

	/// <summary>
	/// Length of the internal state in bytes.
	/// </summary>
	static abstract int StateLen { get; }

	/// <summary>
	/// Computes the hash for the given message.
	/// </summary>
	/// <param name="hash">Output buffer. Must be exactly <see cref="HashLen"/> bytes.</param>
	/// <param name="message">Input message to hash.</param>
	/// <returns>Zero on success; non-zero on failure.</returns>
	static abstract int ComputeHash(
		Span<byte> hash,
		ReadOnlySpan<byte> message);

	/// <summary>
	/// Initializes the hashing state.
	/// </summary>
	/// <param name="state">State buffer. Must be <see cref="StateLen"/> bytes.</param>
	/// <returns>Zero on success; non-zero on failure.</returns>
	static abstract int Init(Span<byte> state);

	/// <summary>
	/// Updates the hashing state with more data.
	/// </summary>
	/// <param name="state">State buffer previously initialized by <see cref="Init"/>.</param>
	/// <param name="message">Data to append to the hash computation.</param>
	/// <returns>Zero on success; non-zero on failure.</returns>
	static abstract int Update(Span<byte> state, ReadOnlySpan<byte> message);

	/// <summary>
	/// Finalizes the hash computation and writes the output.
	/// </summary>
	/// <param name="state">State buffer previously initialized by <see cref="Init"/>.</param>
	/// <param name="hash">Output buffer. Must be exactly <see cref="HashLen"/> bytes.</param>
	/// <returns>Zero on success; non-zero on failure.</returns>
	static abstract int Final(Span<byte> state, Span<byte> hash);
}
