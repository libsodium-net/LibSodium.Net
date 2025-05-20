namespace LibSodium.LowLevel;

/// <summary>
/// Defines a unified interface for HMAC-SHA-2 algorithms.
/// Supports one-shot MAC computation and incremental API (Init, Update, Final).
/// </summary>
internal interface IMac
{
	/// <summary>
	/// Length of the MAC in bytes.
	/// </summary>
	static abstract int MacLen { get; }

	/// <summary>
	/// Length of the secret key in bytes.
	/// </summary>
	static abstract int KeyLen { get; }

	/// <summary>
	/// Length of the internal state in bytes.
	/// </summary>
	static abstract int StateLen { get; }

	/// <summary>
	/// Computes the MAC for the given message and key.
	/// </summary>
	static abstract int ComputeMac(
		Span<byte> mac,
		ReadOnlySpan<byte> message,
		ReadOnlySpan<byte> key);

	/// <summary>
	/// Verifies the MAC for the given message and key.
	/// </summary>
	static abstract int VerifyMac(
		ReadOnlySpan<byte> mac,
		ReadOnlySpan<byte> message,
		ReadOnlySpan<byte> key);

	/// <summary>
	/// Initializes the HMAC state with the given key.
	/// </summary>
	static abstract int Init(
		Span<byte> state,
		ReadOnlySpan<byte> key);

	/// <summary>
	/// Updates the HMAC state with more message data.
	/// </summary>
	static abstract int Update(
		Span<byte> state,
		ReadOnlySpan<byte> message);

	/// <summary>
	/// Finalizes the HMAC computation and writes the MAC.
	/// </summary>
	static abstract int Final(
		Span<byte> state,
		Span<byte> mac);

	/// <summary>
	/// Generates a random key suitable for this MAC algorithm.
	/// </summary>
	static abstract void GenerateKey(Span<byte> key);
}
