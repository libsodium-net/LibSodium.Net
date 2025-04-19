using Shouldly;
using System.Text;
using static LibSodium.XChaCha20Poly1305;

namespace LibSodium.Tests;

public class XChaCha20Poly1305Tests
{
	private static byte[] GenerateRandomBytes(int length)
	{
		var buffer = new byte[length];
		Random.Shared.NextBytes(buffer);
		return buffer;
	}

	[Test]
	public void EncryptAndDecrypt_Combined_WithAutoNonce()
	{
		var key = GenerateRandomBytes(KeyLen);
		var plaintext = GenerateRandomBytes(128);
		var ciphertext = new byte[NonceLen + plaintext.Length + MacLen];
		var decrypted = new byte[plaintext.Length];

		var actual = EncryptCombined(ciphertext, plaintext, key);
		var result = DecryptCombined(decrypted, actual, key);
		result.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public void EncryptAndDecrypt_Combined_WithManualNonce()
	{
		var key = GenerateRandomBytes(KeyLen);
		var nonce = GenerateRandomBytes(NonceLen);
		var plaintext = GenerateRandomBytes(128);
		var ciphertext = new byte[plaintext.Length + MacLen];
		var decrypted = new byte[plaintext.Length];

		var result = EncryptCombined(ciphertext, plaintext, key, default, nonce);
		var output = DecryptCombined(decrypted, result, key, default, nonce);
		output.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public void EncryptAndDecrypt_Detached_WithManualNonce_AndAAD()
	{
		var key = GenerateRandomBytes(KeyLen);
		var nonce = GenerateRandomBytes(NonceLen);
		var aad = GenerateRandomBytes(64);
		var plaintext = GenerateRandomBytes(64);
		var ciphertext = new byte[plaintext.Length];
		var mac = new byte[MacLen];
		var decrypted = new byte[plaintext.Length];

		EncryptDetached(ciphertext, mac, plaintext, key, aad, nonce);
		var result = DecryptDetached(decrypted, ciphertext, key, mac, aad, nonce);
		result.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public void EncryptAndDecrypt_Detached_WithAutoNonce_AndNoAAD()
	{
		var key = GenerateRandomBytes(KeyLen);
		var plaintext = GenerateRandomBytes(64);
		var ciphertext = new byte[NonceLen + plaintext.Length];
		var mac = new byte[MacLen];
		var decrypted = new byte[plaintext.Length];

		var result = EncryptDetached(ciphertext, mac, plaintext, key);
		var nonce = result.Slice(0, NonceLen);
		var cipher = result.Slice(NonceLen);

		var plain = DecryptDetached(decrypted, cipher, key, mac, ReadOnlySpan<byte>.Empty, nonce);
		plain.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public void TamperedCiphertext_ShouldThrow()
	{
		var key = GenerateRandomBytes(KeyLen);
		var plaintext = GenerateRandomBytes(64);
		var ciphertext = new byte[NonceLen + plaintext.Length + MacLen];
		var decrypted = new byte[plaintext.Length];

		var result = EncryptCombined(ciphertext, plaintext, key);
		result[^1] ^= 0xFF;

		Should.Throw<LibSodiumException>(() => DecryptCombined(decrypted, ciphertext, key));
	}

	[Test]
	public void InvalidMac_ShouldThrow()
	{
		var key = GenerateRandomBytes(KeyLen);
		var nonce = GenerateRandomBytes(NonceLen);
		var aad = GenerateRandomBytes(16);
		var plaintext = GenerateRandomBytes(128);
		var ciphertext = new byte[plaintext.Length];
		var mac = new byte[MacLen];
		var decrypted = new byte[plaintext.Length];

		EncryptDetached(ciphertext, mac, plaintext, key, aad, nonce);
		mac[0] ^= 0xFF;

		Should.Throw<LibSodiumException>(() => DecryptDetached(decrypted, ciphertext, key, mac, aad, nonce));
	}

	[Test]
	public void InvalidKeyLength_ShouldThrow()
	{
		var key = GenerateRandomBytes(KeyLen - 1);
		var nonce = GenerateRandomBytes(NonceLen);
		var plaintext = GenerateRandomBytes(64);
		var ciphertext = new byte[plaintext.Length];
		var mac = new byte[MacLen];

		Should.Throw<ArgumentException>(() => EncryptDetached(ciphertext, mac, plaintext, key, ReadOnlySpan<byte>.Empty, nonce));
	}

	[Test]
	public void InvalidNonceLength_ShouldThrow()
	{
		var key = GenerateRandomBytes(KeyLen);
		var nonce = GenerateRandomBytes(12);
		var plaintext = GenerateRandomBytes(64);
		var ciphertext = new byte[plaintext.Length];
		var mac = new byte[MacLen];

		Should.Throw<ArgumentException>(() => EncryptDetached(ciphertext, mac, plaintext, key, ReadOnlySpan<byte>.Empty, nonce));
	}

	[Test]
	public void BufferTooSmall_ShouldThrow()
	{
		var key = GenerateRandomBytes(KeyLen);
		var nonce = GenerateRandomBytes(NonceLen);
		var plaintext = GenerateRandomBytes(64);
		var ciphertext = new byte[plaintext.Length - 1];
		var mac = new byte[MacLen];

		Should.Throw<ArgumentException>(() => EncryptDetached(ciphertext, mac, plaintext, key, ReadOnlySpan<byte>.Empty, nonce));
	}

	//[Test]
	//[Arguments(0)]
	//[Arguments(1)]
	//[Arguments(16)]
	//[Arguments(64)]
	//[Arguments(1024)]
	//public void EncryptAndDecrypt_Combined_VariousLengths(int size)
	//{
	//	var key = GenerateRandomBytes(KeyLen);
	//	var plaintext = GenerateRandomBytes(size);
	//	var ciphertext = new byte[NonceLen + size + MacLen];
	//	var decrypted = new byte[size];

	//	var result = EncryptCombined(ciphertext, plaintext, key);
	//	var plain = DecryptCombined(decrypted, result, key);
	//	plain.ToArray().ShouldBe(plaintext);
	//}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(16)]
	[Arguments(64)]
	[Arguments(1024)]
	public void EncryptAndDecrypt_Detached_VariousLengths(int size)
	{
		var key = GenerateRandomBytes(KeyLen);
		var nonce = GenerateRandomBytes(NonceLen);
		var plaintext = GenerateRandomBytes(size);
		var ciphertext = new byte[size];
		var mac = new byte[MacLen];
		var decrypted = new byte[size];

		EncryptDetached(ciphertext, mac, plaintext, key, ReadOnlySpan<byte>.Empty, nonce);
		var result = DecryptDetached(decrypted, ciphertext, key, mac, ReadOnlySpan<byte>.Empty, nonce);
		result.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public void AllCombinedOptions()
	{
		var key = GenerateRandomBytes(KeyLen);
		var nonce = GenerateRandomBytes(NonceLen);
		var plaintext = GenerateRandomBytes(64);
		var ciphertext = new byte[NonceLen + plaintext.Length + MacLen];
		var decrypted = new byte[plaintext.Length];
		var aad = GenerateRandomBytes(16);
		Span<byte> encrypted;

		encrypted = Encrypt(ciphertext, plaintext, key);
		Decrypt(decrypted, encrypted, key);
		decrypted.SequenceEqual(plaintext).ShouldBeTrue();

		encrypted = Encrypt(ciphertext, plaintext, key, aad: aad);
		Decrypt(decrypted, encrypted, key, aad: aad);
		decrypted.SequenceEqual(plaintext).ShouldBeTrue();

		encrypted = Encrypt(ciphertext, plaintext, key, aad: aad, nonce: nonce);
		Decrypt(decrypted, encrypted, key, aad: aad, nonce: nonce);
		decrypted.SequenceEqual(plaintext).ShouldBeTrue();

		encrypted = Encrypt(ciphertext, plaintext, key, nonce: nonce);
		Decrypt(decrypted, encrypted, key, nonce: nonce);
		decrypted.SequenceEqual(plaintext).ShouldBeTrue();
	}

	[Test]
	public void AllDetachedOptions()
	{
		var key = GenerateRandomBytes(KeyLen);
		var nonce = GenerateRandomBytes(NonceLen);
		var plaintext = GenerateRandomBytes(64);
		var ciphertext = new byte[NonceLen + plaintext.Length + MacLen];
		var decrypted = new byte[plaintext.Length];
		var aad = GenerateRandomBytes(16);
		var mac = new byte[MacLen];

		Span<byte> encrypted;

		encrypted = Encrypt(ciphertext, plaintext, key, mac: mac);
		Decrypt(decrypted, encrypted, key, mac: mac);
		decrypted.SequenceEqual(plaintext).ShouldBeTrue();

		encrypted = Encrypt(ciphertext, plaintext, key, mac: mac, aad: aad);
		Decrypt(decrypted, encrypted, key, mac: mac, aad: aad);
		decrypted.SequenceEqual(plaintext).ShouldBeTrue();

		encrypted = Encrypt(ciphertext, plaintext, key, mac: mac, aad: aad, nonce: nonce);
		Decrypt(decrypted, encrypted, key, mac: mac, aad: aad, nonce: nonce);
		decrypted.SequenceEqual(plaintext).ShouldBeTrue();

		encrypted = Encrypt(ciphertext, plaintext, key, mac: mac, nonce: nonce);
		Decrypt(decrypted, encrypted, key, mac: mac, nonce: nonce);
		decrypted.SequenceEqual(plaintext).ShouldBeTrue();
	}

	[Test]
	public void Example()
	{
Span<byte> key = stackalloc byte[XChaCha20Poly1305.KeyLen];
RandomGenerator.Fill(key);

var aad = Encoding.UTF8.GetBytes("context");
var data = Encoding.UTF8.GetBytes("Hello");

var ciphertext = new byte[data.Length + MacLen + NonceLen];
XChaCha20Poly1305.Encrypt(ciphertext, data, key, aad: aad);

var decrypted = new byte[data.Length];
XChaCha20Poly1305.Decrypt(decrypted, ciphertext, key, aad: aad);

var isWorking = decrypted.SequenceEqual(data);
Console.WriteLine($"It works: {isWorking}");
	}
}
