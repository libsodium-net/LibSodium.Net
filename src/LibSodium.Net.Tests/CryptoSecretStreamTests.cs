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
		public void GenerateKey_GeneratesRandomKey()
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

			Span<byte> cleartext = stackalloc byte[48];
			RandomGenerator.Fill(cleartext);

			Span<byte> ciphertext = stackalloc byte[cleartext.Length + CryptoSecretStream.OverheadLen];

			var encrypted = CryptoSecretStream.EncryptChunk(state, ciphertext, cleartext, CryptoSecretStreamTag.Message);
			encrypted.Length.ShouldBe(cleartext.Length + CryptoSecretStream.OverheadLen);

			SecureBigUnsignedInteger.Equals(cleartext, encrypted.Slice(0, cleartext.Length)).ShouldBeFalse(); // Ensure it's encrypted
			SecureBigUnsignedInteger.Equals(cleartext, encrypted.Slice(CryptoSecretStream.OverheadLen)).ShouldBeFalse(); // Ensure it's encrypted
		}

		[Test]
		public void EncryptChunk_WithAAD_ReturnsCiphertextWithOverhead()
		{
			Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen];
			CryptoSecretStream.GenerateKey(key);

			Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
			Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen];
			CryptoSecretStream.InitializeEncryption(state, header, key);

			Span<byte> cleartext = stackalloc byte[48];
			RandomGenerator.Fill(cleartext);

			Span<byte> additionalData = stackalloc byte[16];
			RandomGenerator.Fill(additionalData);

			Span<byte> ciphertext = stackalloc byte[cleartext.Length + CryptoSecretStream.OverheadLen];

			var encrypted = CryptoSecretStream.EncryptChunk(state, ciphertext, cleartext, CryptoSecretStreamTag.Message, additionalData);
			encrypted.Length.ShouldBe(cleartext.Length + CryptoSecretStream.OverheadLen);

			SecureBigUnsignedInteger.Equals(cleartext, encrypted.Slice(0, cleartext.Length)).ShouldBeFalse(); // Ensure it's encrypted
			SecureBigUnsignedInteger.Equals(cleartext, encrypted.Slice(CryptoSecretStream.OverheadLen)).ShouldBeFalse(); // Ensure it's encrypted

		}

		[Test]
		public void EncryptChunk_ThrowsArgumentException_ForInvalidStateLen()
		{

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> cleartext = stackalloc byte[48];
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen + 1];
				Span<byte> ciphertext = stackalloc byte[cleartext.Length + CryptoSecretStream.OverheadLen];

				CryptoSecretStream.EncryptChunk(state, ciphertext, cleartext, CryptoSecretStreamTag.Message);
			});
		}

		[Test]
		public void EncryptChunk_ThrowsArgumentException_ForInvalidCipherTextLen()
		{

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> cleartext = stackalloc byte[48];
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];
				Span<byte> ciphertext = stackalloc byte[cleartext.Length + CryptoSecretStream.OverheadLen - 1];

				CryptoSecretStream.EncryptChunk(state, ciphertext, cleartext, CryptoSecretStreamTag.Message);
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
				Span<byte> cleartext = stackalloc byte[48];
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen + 1];
				Span<byte> ciphertext = stackalloc byte[cleartext.Length + CryptoSecretStream.OverheadLen];

				CryptoSecretStream.DecryptChunk(state, cleartext , out var _, ciphertext);
			});
		}

		[Test]
		public void DecryptChunk_ThrowsArgumentException_ForInvalidCleartextLen()
		{

			Should.Throw<ArgumentException>(() =>
			{
				Span<byte> ciphertext = stackalloc byte[48 + CryptoSecretStream.OverheadLen];
				Span<byte> cleartext = stackalloc byte[ciphertext.Length - CryptoSecretStream.OverheadLen - 1];
				Span<byte> state = stackalloc byte[CryptoSecretStream.StateLen];

				CryptoSecretStream.DecryptChunk(state, cleartext, out var _, ciphertext);
			});
		}

		[Test]
		public void DecryptChunk_ThrowsLibSodiumException_ForTamperedCiphertext()
		{
			Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen];
			CryptoSecretStream.GenerateKey(key);

			Span<byte> header = stackalloc byte[CryptoSecretStream.HeaderLen];
			var state = new byte[CryptoSecretStream.StateLen];

			CryptoSecretStream.InitializeEncryption(state, header, key);

			Span<byte> cleartext = stackalloc byte[48];
			RandomGenerator.Fill(cleartext);

			var ciphertext = new byte[cleartext.Length + CryptoSecretStream.OverheadLen];
			CryptoSecretStream.EncryptChunk(state, ciphertext, cleartext, CryptoSecretStreamTag.Message);

			// Tamper with the ciphertext
			ciphertext[5]++;

			CryptoSecretStream.InitializeDecryption(state, header, key);
			Should.Throw<LibSodiumException>(() =>
			{
				Span<byte> decrypted = stackalloc byte[ciphertext.Length - CryptoSecretStream.OverheadLen] ;
				CryptoSecretStream.DecryptChunk(state, decrypted, out _, ciphertext);
			});
		}

		[Test]
		public void DecryptChunk_With_AAD_Throws_LibSodiumException_ForIncorrect_AAD()
		{
			var key = GenerateRandomBytes(CryptoSecretStream.KeyLen);
			var stateEncrypt = new byte[CryptoSecretStream.StateLen];
			var header = new byte[CryptoSecretStream.HeaderLen];
			CryptoSecretStream.InitializeEncryption(stateEncrypt, header, key);
			var cleartextOriginal = GenerateRandomBytes(32);
			var additionalDataOriginal = GenerateRandomBytes(16);
			var ciphertext = new byte[cleartextOriginal.Length + CryptoSecretStream.OverheadLen];
			var encrypted = CryptoSecretStream.EncryptChunk(stateEncrypt, ciphertext, cleartextOriginal, CryptoSecretStreamTag.Message, additionalDataOriginal).ToArray();

			var stateDecrypt = new byte[CryptoSecretStream.StateLen];
			CryptoSecretStream.InitializeDecryption(stateDecrypt, header, key);
			var cleartextDecrypted = new byte[encrypted.Length - CryptoSecretStream.OverheadLen];
			var additionalDataWrong = GenerateRandomBytes(16);
			Should.Throw<LibSodiumException>(() => CryptoSecretStream.DecryptChunk(stateDecrypt, cleartextDecrypted, out _, encrypted, additionalDataWrong));
		}
	}
}