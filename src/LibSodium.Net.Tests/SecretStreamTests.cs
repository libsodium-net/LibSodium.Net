using System.Text;

namespace LibSodium.Tests;

public class SecretStreamTests
{
	private static byte[] GenerateRandomBytes(int length)
	{
		var bytes = new byte[length];
		Random.Shared.NextBytes(bytes);
		return bytes;
	}


	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(SecretStream.PlainChunkSize - 1)]
	[Arguments(SecretStream.PlainChunkSize)]
	[Arguments(SecretStream.PlainChunkSize + 1)]
	[Arguments(SecretStream.PlainChunkSize * 2 - 1)]
	[Arguments(SecretStream.PlainChunkSize * 2)]
	[Arguments(SecretStream.PlainChunkSize * 2 + 1)]
	public async Task EncryptAndDecryptAsync_Success(int plaintextLen)
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		var plaintext = GenerateRandomBytes(plaintextLen);
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		await SecretStream.EncryptAsync(input, encryptedOutput, key);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();
		await SecretStream.DecryptAsync(encryptedOutput, decryptedOutput, key);
		decryptedOutput.ToArray().ShouldBe(plaintext);
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(SecretStream.PlainChunkSize - 1)]
	[Arguments(SecretStream.PlainChunkSize)]
	[Arguments(SecretStream.PlainChunkSize + 1)]
	[Arguments(SecretStream.PlainChunkSize * 2 - 1)]
	[Arguments(SecretStream.PlainChunkSize * 2)]
	[Arguments(SecretStream.PlainChunkSize * 2 + 1)]
	public void EncryptAndDecrypt_Sync_Success(int plaintextLen)
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		var plaintext = GenerateRandomBytes(plaintextLen); // 64KB data
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		SecretStream.Encrypt(input, encryptedOutput, key);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();
		SecretStream.Decrypt(encryptedOutput, decryptedOutput, key);

		decryptedOutput.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public async Task EncryptAsync_Throws_WithInvalidKey()
	{
		var invalidKey = GenerateRandomBytes(CryptoSecretStream.KeyLen - 1);

		using var input = new MemoryStream();
		using var output = new MemoryStream();

		await AssertLite.ThrowsAsync<ArgumentException>(() => SecretStream.EncryptAsync(input, output, invalidKey));

	}

	[Test]
	public async Task DecryptAsync_Throws_WithInvalidKey()
	{
		var validKey = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(validKey);

		var invalidKey = GenerateRandomBytes(CryptoSecretStream.KeyLen);

		var plaintext = GenerateRandomBytes(64 * 1024);
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		await SecretStream.EncryptAsync(input, encryptedOutput, validKey);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();

		await AssertLite.ThrowsAsync<LibSodiumException>(() => SecretStream.DecryptAsync(encryptedOutput, decryptedOutput, invalidKey));
	}

	[Test]
	public void Encrypt_Throws_WithNullInput()
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		using var output = new MemoryStream();

		AssertLite.Throws<ArgumentNullException>(() => SecretStream.Encrypt(null!, output, key));
	}

	[Test]
	public void Decrypt_Throws_WithTamperedCiphertext()
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		var plaintext = GenerateRandomBytes(64 * 1024);
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		SecretStream.Encrypt(input, encryptedOutput, key);
		var ciphertext = encryptedOutput.ToArray();
		ciphertext[CryptoSecretStream.HeaderLen + 10] ^= 0xFF; // Tamper with ciphertext

		using var tamperedInput = new MemoryStream(ciphertext);
		using var decryptedOutput = new MemoryStream();

		AssertLite.Throws<LibSodiumException>(() => SecretStream.Decrypt(tamperedInput, decryptedOutput, key));
	}

	[Test]
	public void Example()
	{
		Span<byte> key = stackalloc byte[32];
		RandomGenerator.Fill(key);

		const string hello = "Hello LibSodium.Net!";
		var helloData = Encoding.UTF8.GetBytes(hello);

		using var plaintextStream = new MemoryStream();
		using var ciphertextStream = new MemoryStream();
		using var decryptedStream = new MemoryStream();

		plaintextStream.Write(helloData);
		plaintextStream.Position = 0;

		SecretStream.Encrypt(plaintextStream, ciphertextStream, key);
		ciphertextStream.Position = 0;
		SecretStream.Decrypt(ciphertextStream, decryptedStream, key);
		decryptedStream.Position = 0;

		var isWorking = decryptedStream.ToArray().SequenceEqual(helloData);

		isWorking.ShouldBeTrue();

	}

	[Test]
	public async Task EncryptAndDecryptAsync_WithAdditionalData_Success()
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		var plaintext = GenerateRandomBytes(12345);
		var aad = Encoding.UTF8.GetBytes("file:invoice.pdf");
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		await SecretStream.EncryptAsync(input, encryptedOutput, key, aad: aad);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();
		await SecretStream.DecryptAsync(encryptedOutput, decryptedOutput, key, aad: aad);

		decryptedOutput.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public void EncryptAndDecrypt_Sync_WithAdditionalData_Success()
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		var plaintext = GenerateRandomBytes(2048);
		var aad = Encoding.UTF8.GetBytes("context:auth-token");

		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		SecretStream.Encrypt(input, encryptedOutput, key, aad: aad);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();
		SecretStream.Decrypt(encryptedOutput, decryptedOutput, key, aad: aad);

		decryptedOutput.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public async Task DecryptAsync_WithIncorrectAdditionalData_Fails()
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		var plaintext = GenerateRandomBytes(500);
		var aad = Encoding.UTF8.GetBytes("session:A");
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		await SecretStream.EncryptAsync(input, encryptedOutput, key, aad: aad);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();
		var wrongAad = Encoding.UTF8.GetBytes("session:B");

		await AssertLite.ThrowsAsync<LibSodiumException>(() =>
			SecretStream.DecryptAsync(encryptedOutput, decryptedOutput, key, aad: wrongAad));
	}

	[Test]
	public void EncryptAndDecrypt_Sync_WithAdditionalData_Span_Success()
	{
		Span<byte> key = stackalloc byte[CryptoSecretStream.KeyLen];
		RandomGenerator.Fill(key);

		var plaintext = GenerateRandomBytes(8192);
		ReadOnlySpan<byte> aad = "context"u8;

		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		SecretStream.Encrypt(input, encryptedOutput, key, aad: aad);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();
		SecretStream.Decrypt(encryptedOutput, decryptedOutput, key, aad: aad);

		decryptedOutput.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public async Task EncryptAndDecryptAsync_WithAdditionalData_Memory_Success()
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		RandomGenerator.Fill(key);

		var plaintext = GenerateRandomBytes(4321);
		var aad = new byte[] { 1, 2, 3, 4, 5 };

		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		await SecretStream.EncryptAsync(input, encryptedOutput, key, aad: aad);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();
		await SecretStream.DecryptAsync(encryptedOutput, decryptedOutput, key, aad: aad);

		decryptedOutput.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public async Task DecryptAsync_WithWrongAdditionalData_Memory_Fails()
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		RandomGenerator.Fill(key);

		var plaintext = GenerateRandomBytes(1024);
		var aad = new byte[] { 42, 42, 42 };
		var wrongAad = new byte[] { 0, 0, 0 };

		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		await SecretStream.EncryptAsync(input, encryptedOutput, key, aad: aad);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();

		await AssertLite.ThrowsAsync<LibSodiumException>(() =>
			SecretStream.DecryptAsync(encryptedOutput, decryptedOutput, key, aad: wrongAad));
	}

	[Test]
	public void EncryptAndDecrypt_Sync_WithSecureMemoryKeyAndAad_Success()
	{
		using var key = SecureMemory.Create<byte>(CryptoSecretStream.KeyLen);
		RandomGenerator.Fill(key);

		ReadOnlySpan<byte> aad = "some additiional data"u8;
		
		var plaintext = GenerateRandomBytes(777);
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		SecretStream.Encrypt(input, encryptedOutput, key, aad: aad);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();
		SecretStream.Decrypt(encryptedOutput, decryptedOutput, key, aad: aad);

		decryptedOutput.ToArray().ShouldBe(plaintext);
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(SecretStream.PlainChunkSize - 1)]
	[Arguments(SecretStream.PlainChunkSize)]
	[Arguments(SecretStream.PlainChunkSize + 1)]
	[Arguments(SecretStream.PlainChunkSize * 2 - 1)]
	[Arguments(SecretStream.PlainChunkSize * 2)]
	[Arguments(SecretStream.PlainChunkSize * 2 + 1)]
	public async Task EncryptAndDecryptAsync_WithSecureMemoryKey_Success(int plaintextLen)
	{
		using var key = SecureMemory.Create<byte>(CryptoSecretStream.KeyLen);
		RandomGenerator.Fill(key);

		var plaintext = new byte[plaintextLen];
		RandomGenerator.Fill(plaintext);
		using var input = new MemoryStream(plaintext);
		using var encrypted = new MemoryStream();
		using var decrypted = new MemoryStream();

		await SecretStream.EncryptAsync(input, encrypted, key);

		encrypted.Position = 0;
		await SecretStream.DecryptAsync(encrypted, decrypted, key);

		decrypted.ToArray().ShouldBe(plaintext);
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(SecretStream.PlainChunkSize - 1)]
	[Arguments(SecretStream.PlainChunkSize)]
	[Arguments(SecretStream.PlainChunkSize + 1)]
	[Arguments(SecretStream.PlainChunkSize * 2 - 1)]
	[Arguments(SecretStream.PlainChunkSize * 2)]
	[Arguments(SecretStream.PlainChunkSize * 2 + 1)]
	public void EncryptAndDecrypt_WithSecureMemoryKey_Success(int plaintextLen)
	{
		using var key = SecureMemory.Create<byte>(CryptoSecretStream.KeyLen);
		RandomGenerator.Fill(key);

		var plaintext = new byte[plaintextLen];
		RandomGenerator.Fill(plaintext);
		using var input = new MemoryStream(plaintext);
		using var encrypted = new MemoryStream();
		using var decrypted = new MemoryStream();

		SecretStream.Encrypt(input, encrypted, key);

		encrypted.Position = 0;
		SecretStream.Decrypt(encrypted, decrypted, key);

		decrypted.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public async Task EncryptAndDecryptAsync_WithSecureMemoryKeyAndAAD_Success()
	{
		using var key = SecureMemory.Create<byte>(CryptoSecretStream.KeyLen);
		RandomGenerator.Fill(key);
		var aad = "aad:secure"u8.ToArray();

		var plaintext = new byte[9999];
		RandomGenerator.Fill(plaintext);
		using var input = new MemoryStream(plaintext);
		using var encrypted = new MemoryStream();
		using var decrypted = new MemoryStream();

		await SecretStream.EncryptAsync(input, encrypted, key, aad);

		encrypted.Position = 0;
		await SecretStream.DecryptAsync(encrypted, decrypted, key, aad);

		decrypted.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public void EncryptAndDecrypt_WithSecureMemoryKeyAndAAD_Success()
	{
		using var key = SecureMemory.Create<byte>(CryptoSecretStream.KeyLen);
		RandomGenerator.Fill(key);
		ReadOnlySpan<byte> aad = "secure aad span"u8;

		var plaintext = new byte[4321];
		RandomGenerator.Fill(plaintext);
		using var input = new MemoryStream(plaintext);
		using var encrypted = new MemoryStream();
		using var decrypted = new MemoryStream();

		SecretStream.Encrypt(input, encrypted, key, aad);

		encrypted.Position = 0;
		SecretStream.Decrypt(encrypted, decrypted, key, aad);

		decrypted.ToArray().ShouldBe(plaintext);
	}


}
