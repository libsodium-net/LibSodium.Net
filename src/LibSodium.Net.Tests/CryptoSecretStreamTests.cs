using Shouldly;
using System;

namespace LibSodium.Tests
{
	public class CryptoSecretStreamTests
	{
		private static byte[] GenerateRandomBytes(int length)
		{
			var bytes = new byte[length];
			Random.Shared.NextBytes(bytes);
			return bytes;
		}

		[Test]
		public void GenerateKey_CreatesKeyOfCorrectLength()
		{
			Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen];
			CryptoSecretStream.GenerateKey(key);
			SecureMemory.IsZero(key).ShouldBeFalse(); // Ensure it's not just zeroed out
		}

		[Test]
		public void GenerateKey_ThrowsArgumentException_ForInvalidKeyLength()
		{
			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen - 1];
				CryptoSecretStream.GenerateKey(key);
			});

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen + 1];
				CryptoSecretStream.GenerateKey(key);
			});
		}

		[Test]
		public void InitializeEncryption_WithValidArguments_FillsHeader_WithSomeNonZeroes()
		{
			Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen];
			Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
			Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen];

			CryptoSecretStream.GenerateKey(key);
			CryptoSecretStream.InitializeEncryption(state, header, key);
			SecureMemory.IsZero(header).ShouldBeFalse();
		}

		[Test]
		public void InitializeEncryption_ThrowsArgumentException_ForInvalidLengths()
		{
			var key = GenerateRandomBytes(CryptoSecretStream.KeyLen);
			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen - 1];
				Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen];
				CryptoSecretStream.InitializeEncryption(state, header, key);
			});

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
				Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen - 1];
				CryptoSecretStream.InitializeEncryption(state, header, key);
			});

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
				Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen - 1];
				CryptoSecretStream.InitializeEncryption(state, header, key.AsSpan().Slice(1));
			});
		}

		[Test]
		public void EncryptChunk_ReturnsCiphertextWithOverhead()
		{
			Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen];
			CryptoSecretStream.GenerateKey(key);

			Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
			Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen];
			CryptoSecretStream.InitializeEncryption(state, header, key);

			Span<byte> clearText = stackalloc byte[48];
			RandomGenerator.Fill(clearText);

			Span<byte> cipherText = stackalloc byte[clearText.Length + CryptoSecretStream.OverheadLen];

			var encrypted = CryptoSecretStream.EncryptChunk(state, cipherText, clearText, CryptoSecretStreamTag.Message);
			encrypted.Length.ShouldBe(clearText.Length + CryptoSecretStream.OverheadLen);

			SecureBigUnsignedInteger.Equals(clearText, encrypted.Slice(0, clearText.Length)).ShouldBeFalse(); // Ensure it's encrypted
			SecureBigUnsignedInteger.Equals(clearText, encrypted.Slice(CryptoSecretStream.OverheadLen)).ShouldBeFalse(); // Ensure it's encrypted
		}

		[Test]
		public void EncryptChunk_WithAAD_ReturnsCiphertextWithOverhead()
		{
			Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen];
			CryptoSecretStream.GenerateKey(key);

			Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
			Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen];
			CryptoSecretStream.InitializeEncryption(state, header, key);

			Span<byte> clearText = stackalloc byte[48];
			RandomGenerator.Fill(clearText);

			Span<byte> additionalData = stackalloc byte[16];
			RandomGenerator.Fill(additionalData);

			Span<byte> cipherText = stackalloc byte[clearText.Length + CryptoSecretStream.OverheadLen];

			var encrypted = CryptoSecretStream.EncryptChunk(state, cipherText, clearText, CryptoSecretStreamTag.Message, additionalData);
			encrypted.Length.ShouldBe(clearText.Length + CryptoSecretStream.OverheadLen);

			SecureBigUnsignedInteger.Equals(clearText, encrypted.Slice(0, clearText.Length)).ShouldBeFalse(); // Ensure it's encrypted
			SecureBigUnsignedInteger.Equals(clearText, encrypted.Slice(CryptoSecretStream.OverheadLen)).ShouldBeFalse(); // Ensure it's encrypted

		}

		[Test]
		public void EncryptChunk_ThrowsArgumentException_ForInvalidStateLen()
		{

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> clearText = stackalloc byte[48];
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen + 1];
				Span<byte> cipherText = stackalloc byte[clearText.Length + CryptoSecretStream.OverheadLen];

				CryptoSecretStream.EncryptChunk(state, cipherText, clearText, CryptoSecretStreamTag.Message);
			});
		}

		[Test]
		public void EncryptChunk_ThrowsArgumentException_ForInvalidCipherTextLen()
		{

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> clearText = stackalloc byte[48];
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
				Span<byte> cipherText = stackalloc byte[clearText.Length + CryptoSecretStream.OverheadLen - 1];

				CryptoSecretStream.EncryptChunk(state, cipherText, clearText, CryptoSecretStreamTag.Message);
			});
		}

		[Test]
		public void InitializeDecryption_DoesNotThrow_WithValidArgumentLengths()
		{
			
			Should.NotThrow(() =>
			{
				Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen];
				CryptoSecretStream.GenerateKey(key);
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
				Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen];
				RandomGenerator.Fill(header);
				CryptoSecretStream.InitializeDecryption(state, header, key);
			});
		}

		[Test]
		public void InitializeDecryption_ThrowsArgumentException_ForInvalidLengths()
		{
			var key = GenerateRandomBytes(CryptoSecretStream.KeyLen);
			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen - 1];
				Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen];
				CryptoSecretStream.InitializeDecryption(state, header, key);
			});

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
				Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen - 1];
				CryptoSecretStream.InitializeDecryption(state, header, key);
			});

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
				Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen - 1];
				CryptoSecretStream.InitializeDecryption(state, header, key.AsSpan().Slice(1));
			});
		}

		[Test]
		public void EncryptAndDecryptChunk_WithoutAAD_Success()
		{

			Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen];
			CryptoSecretStream.GenerateKey(key);

			Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
			Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen];

			CryptoSecretStream.InitializeEncryption(state, header, key);

			Span<byte> cleartext = stackalloc byte[48];
			RandomGenerator.Fill(cleartext);

			Span<byte> ciphertext = new byte[cleartext.Length + CryptoSecretStream.OverheadLen];
			var encrypted = CryptoSecretStream.EncryptChunk(state, ciphertext, cleartext, CryptoSecretStreamTag.Message);
			
			CryptoSecretStream.InitializeDecryption(state, header, key);
			Span<byte> decrypted = new byte[cleartext.Length];
			CryptoSecretStream.DecryptChunk(state, decrypted, out var tag, encrypted);

			SecureMemory.Equals(decrypted, cleartext).ShouldBeTrue();
			tag.ShouldBe(CryptoSecretStreamTag.Message);
		}

		[Test]
		public void EncryptAndDecryptChunk_WithAAD_Success()
		{
			Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen];
			CryptoSecretStream.GenerateKey(key);

			Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
			Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen];

			CryptoSecretStream.InitializeEncryption(state, header, key);

			Span<byte> cleartext = stackalloc byte[48];
			RandomGenerator.Fill(cleartext);

			Span<byte> ad = stackalloc byte[16];
			RandomGenerator.Fill(ad);

			Span<byte> ciphertext = stackalloc byte[cleartext.Length + CryptoSecretStream.OverheadLen];
			var encrypted = CryptoSecretStream.EncryptChunk(state, ciphertext, cleartext, CryptoSecretStreamTag.Message, ad);

			CryptoSecretStream.InitializeDecryption(state, header, key);
			Span<byte> decrypted = stackalloc byte[cleartext.Length];
			CryptoSecretStream.DecryptChunk(state, decrypted, out var tag, encrypted, ad);

			SecureMemory.Equals(decrypted, cleartext).ShouldBeTrue();
			tag.ShouldBe(CryptoSecretStreamTag.Message);
		}

		[Test]
		public void DecryptChunk_ThrowsArgumentException_ForInvalidStateLen()
		{

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> clearText = stackalloc byte[48];
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen + 1];
				Span<byte> cipherText = stackalloc byte[clearText.Length + CryptoSecretStream.OverheadLen];

				CryptoSecretStream.DecryptChunk(state, clearText , out var _, cipherText);
			});
		}

		[Test]
		public void DecryptChunk_ThrowsArgumentException_ForInvalidCleartextLen()
		{

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> cipherText = stackalloc byte[48 + CryptoSecretStream.OverheadLen];
				Span<byte> clearText = stackalloc byte[cipherText.Length - CryptoSecretStream.OverheadLen - 1];
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];

				CryptoSecretStream.DecryptChunk(state, clearText, out var _, cipherText);
			});
		}

		[Test]
		public void DecryptChunk_ThrowsLibSodiumException_ForTamperedCiphertext()
		{
			var key = GenerateRandomBytes(CryptoSecretStream.KeyLen);
			var stateEncrypt = new byte[CryptoSecretStream.StateLen];
			var header = new byte[CryptoSecretStream.HeaderLen];
			CryptoSecretStream.InitializeEncryption(stateEncrypt, header, key);
			var clearTextOriginal = GenerateRandomBytes(32);
			var cipherText = new byte[clearTextOriginal.Length + CryptoSecretStream.OverheadLen];
			var encrypted = CryptoSecretStream.EncryptChunk(stateEncrypt, cipherText, clearTextOriginal, CryptoSecretStreamTag.Message).ToArray();

			// Tamper with the ciphertext
			encrypted[5]++;

			var stateDecrypt = new byte[CryptoSecretStream.StateLen];
			CryptoSecretStream.InitializeDecryption(stateDecrypt, header, key);
			var clearTextDecrypted = new byte[encrypted.Length - CryptoSecretStream.OverheadLen];
			Should.Throw<LibSodiumException>(() => CryptoSecretStream.DecryptChunk(stateDecrypt, clearTextDecrypted, out _, encrypted));
		}

		[Test]
		public void DecryptChunk_WithAAD_ThrowsLibSodiumException_ForIncorrectAAD()
		{
			var key = GenerateRandomBytes(CryptoSecretStream.KeyLen);
			var stateEncrypt = new byte[CryptoSecretStream.StateLen];
			var header = new byte[CryptoSecretStream.HeaderLen];
			CryptoSecretStream.InitializeEncryption(stateEncrypt, header, key);
			var clearTextOriginal = GenerateRandomBytes(32);
			var additionalDataOriginal = GenerateRandomBytes(16);
			var cipherText = new byte[clearTextOriginal.Length + CryptoSecretStream.OverheadLen];
			var encrypted = CryptoSecretStream.EncryptChunk(stateEncrypt, cipherText, clearTextOriginal, CryptoSecretStreamTag.Message, additionalDataOriginal).ToArray();

			var stateDecrypt = new byte[CryptoSecretStream.StateLen];
			CryptoSecretStream.InitializeDecryption(stateDecrypt, header, key);
			var clearTextDecrypted = new byte[encrypted.Length - CryptoSecretStream.OverheadLen];
			var additionalDataWrong = GenerateRandomBytes(16);
			Should.Throw<LibSodiumException>(() => CryptoSecretStream.DecryptChunk(stateDecrypt, clearTextDecrypted, out _, encrypted, additionalDataWrong));
		}
	}
}