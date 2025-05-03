using Shouldly;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibSodium.Net.Tests
{
	internal class AeadCoreTestBase<T> where T : LowLevel.IAead
	{
		public static byte[] GenerateRandomBytes(int length)
		{
			var buffer = new byte[length];
			Random.Shared.NextBytes(buffer);
			return buffer;
		}

		public static void EncryptAndDecrypt_Combined_WithAutoNonce()
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var plaintext = GenerateRandomBytes(128);
			var ciphertext = new byte[T.NonceLen + plaintext.Length + T.MacLen];
			var decrypted = new byte[plaintext.Length];

			var actual = AeadCore<T>.Encrypt(ciphertext, plaintext, key);
			var result = AeadCore<T>.Decrypt(decrypted, actual, key);
			result.ToArray().ShouldBe(plaintext);
		}

		public static void EncryptAndDecrypt_Combined_WithManualNonce()
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var nonce = GenerateRandomBytes(T.NonceLen);
			var plaintext = GenerateRandomBytes(128);
			var ciphertext = new byte[plaintext.Length + T.MacLen];
			var decrypted = new byte[plaintext.Length];

			var result = AeadCore<T>.Encrypt(ciphertext, plaintext, key, nonce: nonce);
			var output = AeadCore<T>.Decrypt(decrypted, result, key, nonce: nonce);
			output.ToArray().ShouldBe(plaintext);
		}

		public static void EncryptAndDecrypt_Detached_WithManualNonce_AndAAD()
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var nonce = GenerateRandomBytes(T.NonceLen);
			var aad = GenerateRandomBytes(64);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[plaintext.Length];
			var mac = new byte[T.MacLen];
			var decrypted = new byte[plaintext.Length];

			AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac: mac, aad: aad, nonce: nonce);
			var result = AeadCore<T>.Decrypt(decrypted, ciphertext, key, mac: mac, aad: aad, nonce: nonce);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();
		}

		public static void EncryptAndDecrypt_Detached_WithAutoNonce_AndNoAAD()
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[T.NonceLen + plaintext.Length];
			var mac = new byte[T.MacLen];
			var decrypted = new byte[plaintext.Length];

			AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac: mac);
			AeadCore<T>.Decrypt(decrypted, ciphertext, key, mac: mac);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();
		}

		public static void TamperedCiphertext_ShouldThrow()
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[T.NonceLen + plaintext.Length + T.MacLen];
			var decrypted = new byte[plaintext.Length];

			var result = AeadCore<T>.Encrypt(ciphertext, plaintext, key);
			result[^1] ^= 0xFF;

			Should.Throw<LibSodiumException>(() => AeadCore<T>.Decrypt(decrypted, ciphertext, key));
		}

		public static void InvalidMac_ShouldThrow()
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var nonce = GenerateRandomBytes(T.NonceLen);
			var aad = GenerateRandomBytes(16);
			var plaintext = GenerateRandomBytes(128);
			var ciphertext = new byte[plaintext.Length];
			var mac = new byte[T.MacLen];
			var decrypted = new byte[plaintext.Length];

			AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac, aad, nonce);
			mac[0] ^= 0xFF;

			Should.Throw<LibSodiumException>(() => AeadCore<T>.Decrypt(decrypted, ciphertext, key, mac, aad, nonce));
		}

		public static void InvalidKeyLength_ShouldThrow()
		{
			var key = GenerateRandomBytes(T.KeyLen - 1);
			var nonce = GenerateRandomBytes(T.NonceLen);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[plaintext.Length];
			var mac = new byte[T.MacLen];

			Should.Throw<ArgumentException>(() => AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac: mac, nonce: nonce));
		}

		public static void InvalidNonceLength_ShouldThrow()
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var nonce = GenerateRandomBytes(T.NonceLen - 1);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[plaintext.Length];
			var mac = new byte[T.MacLen];

			Should.Throw<ArgumentException>(() => AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac: mac, nonce: nonce));
		}

		public static void BufferTooSmall_ShouldThrow()
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var nonce = GenerateRandomBytes(T.NonceLen);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[plaintext.Length - 1];
			var mac = new byte[T.MacLen];
			Should.Throw<ArgumentException>(() => AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac: mac, nonce: nonce));
		}

		public static void EncryptAndDecrypt_Detached_VariousLengths(int size)
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var nonce = GenerateRandomBytes(T.NonceLen);
			var plaintext = GenerateRandomBytes(size);
			var ciphertext = new byte[size];
			var mac = new byte[T.MacLen];
			var decrypted = new byte[size];

			AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac: mac, nonce: nonce);
			AeadCore<T>.Decrypt(decrypted, ciphertext, key, mac: mac, nonce: nonce);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();
		}

		public static void AllCombinedOptions()
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var nonce = GenerateRandomBytes(T.NonceLen);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[T.NonceLen + plaintext.Length + T.MacLen];
			var decrypted = new byte[plaintext.Length];
			var aad = GenerateRandomBytes(16);
			Span<byte> encrypted;

			encrypted = AeadCore<T>.Encrypt(ciphertext, plaintext, key);
			AeadCore<T>.Decrypt(decrypted, encrypted, key);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();

			encrypted = AeadCore<T>.Encrypt(ciphertext, plaintext, key, aad: aad);
			AeadCore<T>.Decrypt(decrypted, encrypted, key, aad: aad);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();

			encrypted = AeadCore<T>.Encrypt(ciphertext, plaintext, key, aad: aad, nonce: nonce);
			AeadCore<T>.Decrypt(decrypted, encrypted, key, aad: aad, nonce: nonce);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();

			encrypted = AeadCore<T>.Encrypt(ciphertext, plaintext, key, nonce: nonce);
			AeadCore<T>.Decrypt(decrypted, encrypted, key, nonce: nonce);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();
		}

		public static void AllDetachedOptions()
		{
			var key = GenerateRandomBytes(T.KeyLen);
			var nonce = GenerateRandomBytes(T.NonceLen);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[T.NonceLen + plaintext.Length];
			var decrypted = new byte[plaintext.Length];
			var aad = GenerateRandomBytes(16);
			var mac = new byte[T.MacLen];

			Span<byte> encrypted;

			encrypted = AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac: mac);
			AeadCore<T>.Decrypt(decrypted, encrypted, key, mac: mac);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();

			encrypted = AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac: mac, aad: aad);
			AeadCore<T>.Decrypt(decrypted, encrypted, key, mac: mac, aad: aad);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();

			encrypted = AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac: mac, aad: aad, nonce: nonce);
			AeadCore<T>.Decrypt(decrypted, encrypted, key, mac: mac, aad: aad, nonce: nonce);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();

			encrypted = AeadCore<T>.Encrypt(ciphertext, plaintext, key, mac: mac, nonce: nonce);
			AeadCore<T>.Decrypt(decrypted, encrypted, key, mac: mac, nonce: nonce);
			decrypted.SequenceEqual(plaintext).ShouldBeTrue();
		}
	}
}
