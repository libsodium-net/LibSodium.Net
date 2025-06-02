using LibSodium.Interop;

namespace LibSodium.LowLevel
{
	internal readonly struct CryptoBox
	{
		public static int PublicKeyLen => Native.CRYPTO_BOX_PUBLICKEYBYTES;
		public static int PrivateKeyLen => Native.CRYPTO_BOX_SECRETKEYBYTES;
		public static int SharedKeyLen => Native.CRYPTO_BOX_BEFORENMBYTES;
		public static int NonceLen => Native.CRYPTO_BOX_NONCEBYTES;
		public static int MacLen => Native.CRYPTO_BOX_MACBYTES;
		public static int SeedLen => Native.CRYPTO_BOX_SEEDBYTES;

		public static int GenerateKeypair(Span<byte> publicKey, Span<byte> privateKey)
			=> Native.crypto_box_keypair(publicKey, privateKey);

		public static int GenerateKeypairDeterministically(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed)
			=> Native.crypto_box_seed_keypair(publicKey, privateKey, seed);

		public static int CalculatePublicKey(Span<byte> publicKey, ReadOnlySpan<byte> privateKey)
			=> Native.crypto_scalarmult_base(publicKey, privateKey);

		public static int CalculateSharedKey(Span<byte> sharedKey, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
			=> Native.crypto_box_beforenm(sharedKey, publicKey, privateKey);

		public static int EncryptCombined(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
			=> Native.crypto_box_easy(ciphertext, plaintext, (ulong)plaintext.Length, nonce, publicKey, privateKey);

		public static int DecryptCombined(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
			=> Native.crypto_box_open_easy(plaintext, ciphertext, (ulong)ciphertext.Length, nonce, publicKey, privateKey);

		public static int EncryptDetached(Span<byte> ciphertext, Span<byte> mac, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
			=> Native.crypto_box_detached(ciphertext, mac, plaintext, (ulong)plaintext.Length, nonce, publicKey, privateKey);

		public static int DecryptDetached(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
			=> Native.crypto_box_open_detached(plaintext, ciphertext, mac, (ulong)ciphertext.Length, nonce, publicKey, privateKey);

		public static int EncryptCombinedWithSharedKey(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> sharedKey)
			=> Native.crypto_box_easy_afternm(ciphertext, plaintext, (ulong)plaintext.Length, nonce, sharedKey);

		public static int DecryptCombinedWithSharedKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> sharedKey)
			=> Native.crypto_box_open_easy_afternm(plaintext, ciphertext, (ulong)ciphertext.Length, nonce, sharedKey);

		public static int EncryptDetachedWithSharedKey(Span<byte> ciphertext, Span<byte> mac, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> sharedKey)
			=> Native.crypto_box_detached_afternm(ciphertext, mac, plaintext, (ulong)plaintext.Length, nonce, sharedKey);

		public static int DecryptDetachedWithSharedKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> sharedKey)
			=> Native.crypto_box_open_detached_afternm(plaintext, ciphertext, mac, (ulong)ciphertext.Length, nonce, sharedKey);

		public static int EncryptWithPublicKey(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> publicKey)
			=> Native.crypto_box_seal(ciphertext, plaintext, (ulong)plaintext.Length, publicKey);

		public static int DecryptWithPrivateKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
			=> Native.crypto_box_seal_open(plaintext, ciphertext, (ulong)ciphertext.Length, publicKey, privateKey);
	}
}
