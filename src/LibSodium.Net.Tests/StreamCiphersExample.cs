//using System;
//using System.Collections.Generic;
//using System.Diagnostics;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;

//namespace LibSodium.Net.Tests
//{
//	public class StreamCiphersExample
//	{
//		[Test]
//		public async Task Example()
//		{
//// Async overloads accept Memory<byte>/ReadOnlyMemory<byte>, not Span<byte>.
//// We use byte[] because it implicitly converts to both Memory<byte> and Span<byte>.
//byte[] key = new byte[CryptoStreamXChaCha20.KeyLen];
//byte[] nonce = new byte[CryptoStreamXChaCha20.NonceLen];
//RandomGenerator.Fill(key);
//RandomGenerator.Fill(nonce);

//// 1. Basic usage encrypt and decrypt buffer
//ReadOnlySpan<byte> plaintext = "secret"u8;
//// Encrypting a buffer:
//byte[] ciphertext = new byte[plaintext.Length];
//CryptoStreamXChaCha20.Encrypt(key, nonce, plaintext, ciphertext);
//// Decrypting a buffer:
//byte[] decrypted = new byte[ciphertext.Length];
//CryptoStreamXChaCha20.Decrypt(key, nonce, ciphertext, decrypted);

//// Check that the decrypted buffer matches the original plaintext
//Debug.Assert(plaintext.SequenceEqual(decrypted));

//// 2. Stream-based (sync)
//using (var inputFile = File.OpenRead("video.raw"))
//using (var encryptedFile = File.Create("video.enc"))
//using (var decryptedFile = File.Create("video.dec"))
//{
//	// Encrypting a file:
//	CryptoStreamXChaCha20.Encrypt(key, nonce, inputFile, encryptedFile);
//	// Decrypting a file:
//	encryptedFile.Position = 0; // Reset the position of the encrypted file to the beginning
//	CryptoStreamXChaCha20.Decrypt(key, nonce, encryptedFile, decryptedFile);
//}

//// 3. Stream-based (async)
//using (var inputFile = File.OpenRead("video.raw"))
//using (var encryptedFile = File.Create("video.enc"))
//using (var decryptedFile = File.Create("video.dec"))
//{
//	// Encrypting a file:
//	await CryptoStreamXChaCha20.EncryptAsync(key, nonce, inputFile, encryptedFile);
//	// Decrypting a file:
//	encryptedFile.Position = 0; // Reset the position of the encrypted file to the beginning
//	await CryptoStreamXChaCha20.DecryptAsync(key, nonce, encryptedFile, decryptedFile);
//}

//// 4. Generate raw keystream
//byte[] keystream = new byte[128];
//CryptoStreamXChaCha20.GenerateKeystream(keystream, nonce, key);
//		}
//	}
//}
