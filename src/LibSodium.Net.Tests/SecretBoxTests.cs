using TUnit.Assertions.AssertConditions.Throws;

using static LibSodium.SecretBox;

namespace LibSodium.Tests
{
	public class SecretBoxTests
	{
		private static byte[] GenerateRandomPlainText()
		{
			var plaintextLen = 32 + RandomGenerator.GetUInt32(upperBound: 16);
			var plaintext = new byte[plaintextLen];
			RandomGenerator.Fill(plaintext);
			return plaintext;
		}

		[Test]
		public void EncryptCombined_DecryptCombined_Success()
		{
			Span<byte> key = stackalloc byte[SecretBox.KeyLen];
			Span<byte> nonce = stackalloc byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			Span<byte> ciphertextBuffer = stackalloc byte[plaintext.Length + SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce);
			var ciphertextLen = ciphertext.Length;
			Span<byte> decryptedBuffer = stackalloc byte[plaintext.Length];
			var decrypted = SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key, nonce).ToArray();

			ciphertextLen.ShouldBe(plaintext.Length + SecretBox.MacLen);
			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptCombined_AutoNonce_DecryptCombined_AutoNonce_Success()
		{
			Span<byte> key = stackalloc byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			Span<byte> ciphertextBuffer = stackalloc byte[plaintext.Length + SecretBox.MacLen + SecretBox.NonceLen];

			var ciphertext = SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key);
			Span<byte> decryptedBuffer = stackalloc byte[plaintext.Length];
			var decrypted = SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key).ToArray();
			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptDetached_DecryptDetached_Success()
		{
			Span<byte> key = stackalloc byte[SecretBox.KeyLen];
			Span<byte> nonce = stackalloc byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			Span<byte> ciphertextBuffer = stackalloc byte[plaintext.Length];
			Span<byte> macBuffer = stackalloc byte[SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptDetached(ciphertextBuffer, macBuffer, plaintext, key, nonce);
			Span<byte> decryptedBuffer = stackalloc byte[plaintext.Length];
			var decrypted = SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer, nonce).ToArray();
			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptDetached_AutoNonce_DecryptDetached_AutoNonce_Success()
		{
			Span<byte> key = stackalloc byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			Span<byte> ciphertextBuffer = stackalloc byte[plaintext.Length + SecretBox.NonceLen];
			Span<byte> macBuffer = stackalloc byte[SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptDetached(ciphertextBuffer, macBuffer, plaintext, key);
			Span<byte> decryptedBuffer = stackalloc byte[plaintext.Length];
			var decrypted = SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer).ToArray();

			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptCombined_InvalidCiphertextBuffer_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen - 1]; // Buffer too small

			AssertLite.Throws<ArgumentException>(() =>
			{
				SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce);
			});

		}

		[Test]
		public void EncryptCombined_InvalidKeyLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen - 1];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen];

			AssertLite.Throws<ArgumentException>(() =>
			{
				SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce);
			});
		}

		[Test]
		public void EncryptCombined_InvalidNonceLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen - 1];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen];

			AssertLite.Throws<ArgumentException>(() =>
			{
				SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce);
			});
		}

		[Test]
		public void DecryptCombined_InvalidCiphertextLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			byte[] ciphertextBuffer = new byte[SecretBox.MacLen - 1]; // Buffer too small
			byte[] plaintextBuffer = new byte[10];

			AssertLite.Throws<ArgumentException>(() =>
			{
				SecretBox.DecryptCombined(plaintextBuffer, ciphertextBuffer, key, nonce);
			});
		}

		[Test]
		public void DecryptDetached_InvalidMacLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			byte[] ciphertextBuffer = new byte[10];
			byte[] macBuffer = new byte[SecretBox.MacLen - 1]; // mac too short
			byte[] plaintextBuffer = new byte[10];

			AssertLite.Throws<ArgumentException>(() =>
			{
				SecretBox.DecryptDetached(plaintextBuffer, ciphertextBuffer, key, macBuffer, nonce);
			});
		}

		[Test]
		public void DecryptCombined_TamperedCiphertext_ThrowsSodiumException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce).ToArray(); // Convert to Array to be safe.

			// Tamper with the ciphertext by flipping a bit
			ciphertext[5] ^= 0b00000001; // Flip the 1st bit of the 6th byte

			byte[] decryptedBuffer = new byte[plaintext.Length];

			AssertLite.Throws<LibSodiumException>(() =>
			{
				SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key, nonce);
			});
		}

		[Test]
		public void DecryptCombined_AutoNonce_TamperedCiphertext_ThrowsSodiumException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen + SecretBox.NonceLen];

			var ciphertext = SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key).ToArray(); // Convert to Array to be safe.

			// Tamper with the ciphertext by changing a byte
			ciphertext[SecretBox.NonceLen + 10] ^= 0xFF; // Change the 11th byte after nonce

			byte[] decryptedBuffer = new byte[plaintext.Length];

			AssertLite.Throws<LibSodiumException>(() =>
			{
				SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key);
			});
		}

		[Test]
		public void DecryptDetached_TamperedCiphertext_ThrowsSodiumException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length];
			byte[] macBuffer = new byte[SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptDetached(ciphertextBuffer, macBuffer, plaintext, key, nonce).ToArray(); // Convert to array.

			// Tamper with the ciphertext by flipping a bit
			ciphertext[15] ^= 0b00000001; // Flip the 1st bit of the 16th byte

			byte[] decryptedBuffer = new byte[plaintext.Length];

			AssertLite.Throws<LibSodiumException>(() =>
			{
				SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer, nonce);
			});
		}

		[Test]
		public void DecryptDetached_AutoNonce_TamperedCiphertext_ThrowsSodiumException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.NonceLen];
			byte[] macBuffer = new byte[SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptDetached(ciphertextBuffer, macBuffer, plaintext, key).ToArray(); // Convert to array.

			// Tamper with the ciphertext by changing a byte
			ciphertext[SecretBox.NonceLen + 20] ^= 0xFF; // Change the 21th byte after nonce

			byte[] decryptedBuffer = new byte[plaintext.Length];

			AssertLite.Throws<LibSodiumException>(() =>
			{
				SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer);
			});
		}

		private static byte[] GenerateRandomBytes(int length)
		{
			var buffer = new byte[length];
			Random.Shared.NextBytes(buffer);
			return buffer;
		}

		[Test]
		public void AllCombinedOptions()
		{
			var key = GenerateRandomBytes(KeyLen);
			var nonce = GenerateRandomBytes(NonceLen);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[NonceLen + plaintext.Length + MacLen];
			var decrypted = new byte[plaintext.Length];

			Span<byte> encrypted;

			encrypted = Encrypt(ciphertext, plaintext, key);
			Decrypt(decrypted, encrypted, key);
			decrypted.ShouldBe(plaintext);

			encrypted = Encrypt(ciphertext, plaintext, key, nonce: nonce);
			Decrypt(decrypted, encrypted, key, nonce: nonce);
			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void AllDetachedOptions()
		{
			var key = GenerateRandomBytes(KeyLen);
			var nonce = GenerateRandomBytes(NonceLen);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[NonceLen + plaintext.Length];
			var decrypted = new byte[plaintext.Length];
			var mac = new byte[MacLen];

			Span<byte> encrypted;

			encrypted = Encrypt(ciphertext, plaintext, key, mac: mac);
			Decrypt(decrypted, encrypted, key, mac: mac);
			decrypted.ShouldBe(plaintext);

			encrypted = Encrypt(ciphertext, plaintext, key, mac: mac, nonce: nonce);
			Decrypt(decrypted, encrypted, key, mac: mac, nonce: nonce);
			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptCombinedDecryptCombined_WithSecureMemoryKey_Succeeds()
		{
			using var key = SecureMemory.Create<byte>(KeyLen);
			Span<byte> nonce = stackalloc byte[NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = new byte[64];
			RandomGenerator.Fill(plaintext);
			Span<byte> ciphertext = stackalloc byte[plaintext.Length + MacLen];
			Span<byte> decrypted = stackalloc byte[plaintext.Length];

			var enc = Encrypt(ciphertext, plaintext, key, nonce: nonce);
			var dec = Decrypt(decrypted, enc, key, nonce: nonce);
			dec.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptCombinedAutoNonceDecryptCombinedAutoNonce_WithSecureMemoryKey_Succeeds()
		{
			using var key = SecureMemory.Create<byte>(KeyLen);
			RandomGenerator.Fill(key);

			var plaintext = new byte[48];
			RandomGenerator.Fill(plaintext);
			Span<byte> ciphertext = stackalloc byte[NonceLen + MacLen + plaintext.Length];
			Span<byte> decrypted = stackalloc byte[plaintext.Length];

			var enc = Encrypt(ciphertext, plaintext, key);
			var dec = Decrypt(decrypted, enc, key);
			dec.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptDetachedDecryptDetached_WithSecureMemoryKey_Succeeds()
		{
			using var key = SecureMemory.Create<byte>(KeyLen);
			Span<byte> nonce = stackalloc byte[NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = new byte[32];
			RandomGenerator.Fill(plaintext);
			Span<byte> ciphertext = stackalloc byte[plaintext.Length];
			Span<byte> mac = stackalloc byte[MacLen];
			Span<byte> decrypted = stackalloc byte[plaintext.Length];

			var enc = Encrypt(ciphertext, plaintext, key, mac: mac, nonce: nonce);
			var dec = Decrypt(decrypted, enc, key, mac: mac, nonce: nonce);
			dec.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptDetachedAutoNonceDecryptDetachedAutoNonce_WithSecureMemoryKey_Succeeds()
		{
			using var key = SecureMemory.Create<byte>(KeyLen);
			RandomGenerator.Fill(key);

			var plaintext = new byte[16];
			RandomGenerator.Fill(plaintext);
			Span<byte> ciphertext = stackalloc byte[NonceLen + plaintext.Length];
			Span<byte> mac = stackalloc byte[MacLen];
			Span<byte> decrypted = stackalloc byte[plaintext.Length];

			var enc = Encrypt(ciphertext, plaintext, key, mac: mac);
			var dec = Decrypt(decrypted, enc, key, mac: mac);
			dec.ShouldBe(plaintext);
		}

	}
}