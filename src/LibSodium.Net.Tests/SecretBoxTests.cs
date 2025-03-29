using TUnit.Assertions.AssertConditions.Throws;

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
		public async Task EncryptCombined_DecryptCombined_Success()
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

			await Assert.That(ciphertextLen).IsEqualTo(plaintext.Length + SecretBox.MacLen);
			await Assert.That(decrypted).IsSequenceEqualTo(plaintext);
		}

		[Test]
		public async Task EncryptCombined_AutoNonce_DecryptCombined_AutoNonce_Success()
		{
			Span<byte> key = stackalloc byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			Span<byte> ciphertextBuffer = stackalloc byte[plaintext.Length + SecretBox.MacLen + SecretBox.NonceLen];

			var ciphertext = SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key);
			Span<byte> decryptedBuffer = stackalloc byte[plaintext.Length];
			var decrypted = SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key).ToArray();

			await Assert.That(decrypted).IsSequenceEqualTo(plaintext);
		}

		[Test]
		public async Task EncryptDetached_DecryptDetached_Success()
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

			await Assert.That(decrypted).IsSequenceEqualTo(plaintext);
		}

		[Test]
		public async Task EncryptDetached_AutoNonce_DecryptDetached_AutoNonce_Success()
		{
			Span<byte> key = stackalloc byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			Span<byte> ciphertextBuffer = stackalloc byte[plaintext.Length + SecretBox.NonceLen];
			Span<byte> macBuffer = stackalloc byte[SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptDetached(ciphertextBuffer, macBuffer, plaintext, key);
			Span<byte> decryptedBuffer = stackalloc byte[plaintext.Length];
			var decrypted = SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer).ToArray();

			await Assert.That(decrypted).IsSequenceEqualTo(plaintext);
		}

		[Test]
		public async Task EncryptCombined_InvalidCiphertextBuffer_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen - 1]; // Buffer too small

			await Assert.That(() => SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce)).Throws<ArgumentException>();
		}

		[Test]
		public async Task EncryptCombined_InvalidKeyLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen - 1];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen];

			await Assert.That(() => SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce)).Throws<ArgumentException>();
		}

		[Test]
		public async Task EncryptCombined_InvalidNonceLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen - 1];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen];

			await Assert.That(() => SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce)).Throws<ArgumentException>();
		}

		[Test]
		public async Task DecryptCombined_InvalidCiphertextLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			byte[] ciphertextBuffer = new byte[SecretBox.MacLen - 1]; // Buffer too small
			byte[] plaintextBuffer = new byte[10];

			await Assert.That(() => SecretBox.DecryptCombined(plaintextBuffer, ciphertextBuffer, key, nonce)).Throws<ArgumentException>();
		}

		[Test]
		public async Task DecryptDetached_InvalidMacLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			byte[] ciphertextBuffer = new byte[10];
			byte[] macBuffer = new byte[SecretBox.MacLen - 1]; // mac too short
			byte[] plaintextBuffer = new byte[10];

			await Assert.That(() => SecretBox.DecryptDetached(plaintextBuffer, ciphertextBuffer, key, macBuffer, nonce)).Throws<ArgumentException>();
		}

		[Test]
		public async Task DecryptCombined_TamperedCiphertext_ThrowsSodiumException()
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

			await Assert.That(() => SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key, nonce)).Throws<SodioException>();
		}

		[Test]
		public async Task DecryptCombined_AutoNonce_TamperedCiphertext_ThrowsSodiumException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen + SecretBox.NonceLen];

			var ciphertext = SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key).ToArray(); // Convert to Array to be safe.

			// Tamper with the ciphertext by changing a byte
			ciphertext[SecretBox.NonceLen + 10] ^= 0xFF; // Change the 11th byte after nonce

			byte[] decryptedBuffer = new byte[plaintext.Length];

			await Assert.That(() => SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key)).Throws<SodioException>();
		}

		[Test]
		public async Task DecryptDetached_TamperedCiphertext_ThrowsSodiumException()
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

			await Assert.That(() => SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer, nonce)).Throws<SodioException>();
		}

		[Test]
		public async Task DecryptDetached_AutoNonce_TamperedCiphertext_ThrowsSodiumException()
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

			await Assert.That(() => SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer)).Throws<SodioException>();
		}
	}
}