﻿using Shouldly;
using TUnit;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

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
		decryptedOutput.ToArray().SequenceEqual(plaintext).ShouldBeTrue();
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

		decryptedOutput.ToArray().SequenceEqual(plaintext).ShouldBeTrue();
	}

	[Test]
	public async Task EncryptAsync_Throws_WithInvalidKey()
	{
		var invalidKey = GenerateRandomBytes(CryptoSecretStream.KeyLen - 1);

		using var input = new MemoryStream();
		using var output = new MemoryStream();

		await Should.ThrowAsync<ArgumentException>(() => SecretStream.EncryptAsync(input, output, invalidKey));
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

		await Should.ThrowAsync<LibSodiumException>(() => SecretStream.DecryptAsync(encryptedOutput, decryptedOutput, invalidKey));
	}

	[Test]
	public void Encrypt_Throws_WithNullInput()
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		using var output = new MemoryStream();

		Should.Throw<ArgumentNullException>(() => SecretStream.Encrypt(null!, output, key));
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

		Should.Throw<LibSodiumException>(() => SecretStream.Decrypt(tamperedInput, decryptedOutput, key));
	}
}
