namespace LibSodium.LowLevel
{
	internal interface IAead
	{
		static abstract int KeyLen { get; }
		static abstract int NonceLen { get; }
		static abstract int MacLen { get; }

		static abstract int EncryptDetached(
			Span<byte> ciphertext,
			Span<byte> mac,
			ReadOnlySpan<byte> plaintext,
			ReadOnlySpan<byte> aad,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

		static abstract int DecryptDetached(
			Span<byte> plaintext,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> mac,
			ReadOnlySpan<byte> aad,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

		static abstract int EncryptCombined(
			Span<byte> ciphertext,
			ReadOnlySpan<byte> plaintext,
			ReadOnlySpan<byte> aad,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

		static abstract int DecryptCombined(
			Span<byte> plaintext,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> aad,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);
	}
}
