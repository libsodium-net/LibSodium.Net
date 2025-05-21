namespace LibSodium.LowLevel;

/// <summary>
/// Defines a low-level interface for stream ciphers.
/// Supports XOR encryption/decryption and keystream generation.
/// </summary>
internal interface IStreamCipher
{
	/// <summary>Length of the key in bytes.</summary>
	static abstract int KeyLen { get; }

	/// <summary>Length of the nonce in bytes.</summary>
	static abstract int NonceLen { get; }

	/// <summary>Block size in bytes (typically 64).</summary>
	static abstract int BlockLen { get; }

	/// <summary>
	/// Encrypts or decrypts a message by XORing it with the keystream, starting from block 0.
	/// </summary>
	/// <param name="output">Output buffer to receive ciphertext or plaintext (same length as input).</param>
	/// <param name="message">The input message to encrypt or decrypt.</param>
	/// <param name="nonce">The nonce (unique for each encryption under the same key).</param>
	/// <param name="key">The secret key.</param>
	/// <returns>0 on success, non-zero on failure.</returns>
	static abstract int Xor(
		Span<byte> output,
		ReadOnlySpan<byte> message,
		ReadOnlySpan<byte> nonce,
		ReadOnlySpan<byte> key);

	/// <summary>
	/// Encrypts or decrypts a message using XOR with the keystream, starting from an initial block counter.
	/// </summary>
	/// <param name="output">Output buffer to receive ciphertext or plaintext.</param>
	/// <param name="message">Input message to encrypt/decrypt.</param>
	/// <param name="nonce">The nonce (8 or 24 bytes depending on algorithm).</param>
	/// <param name="key">The secret key (32 bytes).</param>
	/// <param name="initialCounter">Initial block counter (each block = 64 bytes).</param>
	/// <returns>0 on success, non-zero on failure.</returns>
	static abstract int Xor(
		Span<byte> output,
		ReadOnlySpan<byte> message,
		ReadOnlySpan<byte> nonce,
		ReadOnlySpan<byte> key,
		ulong initialCounter);

	/// <summary>
	/// Generates a keystream (without message XOR), starting from block 0.
	/// </summary>
	/// <param name="output">Output buffer to receive the keystream.</param>
	/// <param name="nonce">The nonce.</param>
	/// <param name="key">The secret key.</param>
	/// <returns>0 on success, non-zero on failure.</returns>
	static abstract int GenerateKeystream(
		Span<byte> output,
		ReadOnlySpan<byte> nonce,
		ReadOnlySpan<byte> key);
}