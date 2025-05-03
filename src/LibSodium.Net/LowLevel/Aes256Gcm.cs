using LibSodium.Interop;

namespace LibSodium.LowLevel
{
	internal readonly struct Aes256Gcm : IAead
	{
		public static int KeyLen => Native.CRYPTO_AEAD_AES256GCM_KEYBYTES;
		public static int NonceLen => Native.CRYPTO_AEAD_AES256GCM_NPUBBYTES;
		public static int MacLen => Native.CRYPTO_AEAD_AES256GCM_ABYTES;

		public static int EncryptDetached(Span<byte> ciphertext, Span<byte> mac, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
			=> Native.crypto_aead_aes256gcm_encrypt_detached(ciphertext, mac, out _, plaintext, (ulong)plaintext.Length, aad, (ulong)aad.Length, nuint.Zero, nonce, key);

		public static int DecryptDetached(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
			=> Native.crypto_aead_aes256gcm_decrypt_detached(plaintext, nuint.Zero, ciphertext, (ulong)ciphertext.Length, mac, aad, (ulong)aad.Length, nonce, key);

		public static int EncryptCombined(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
			=> Native.crypto_aead_aes256gcm_encrypt(ciphertext, out _, plaintext, (ulong)plaintext.Length, aad, (ulong)aad.Length, nuint.Zero, nonce, key);

		public static int DecryptCombined(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
			=> Native.crypto_aead_aes256gcm_decrypt(plaintext, out _, nuint.Zero, ciphertext, (ulong)ciphertext.Length, aad, (ulong)aad.Length, nonce, key);
	}
}
