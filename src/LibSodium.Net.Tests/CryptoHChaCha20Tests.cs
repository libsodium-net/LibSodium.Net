namespace LibSodium.Tests;

public class CryptoHChaCha20Tests
{
	[Test]
	public void DerivesSubkey_WithValidParameters()
	{
		Span<byte> subKey = stackalloc byte[CryptoHChaCha20.SubKeyLen];
		Span<byte> masterKey = stackalloc byte[CryptoHChaCha20.KeyLen];
		Span<byte> input = stackalloc byte[CryptoHChaCha20.InputLen];
		Span<byte> context = stackalloc byte[CryptoHChaCha20.ContextLen];
		Random.Shared.NextBytes(masterKey);
		Random.Shared.NextBytes(input);
		Random.Shared.NextBytes(context);

		CryptoHChaCha20.DeriveSubkey(masterKey, subKey, input, context);

		subKey.ShouldNotBeZero();
	}

	[Test]
	public void Throws_When_KeyLengthInvalid()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> invalidKey = stackalloc byte[CryptoHChaCha20.KeyLen - 1];
			Span<byte> subKey = stackalloc byte[CryptoHChaCha20.SubKeyLen];
			Span<byte> input = stackalloc byte[CryptoHChaCha20.InputLen];
			Span<byte> context = stackalloc byte[CryptoHChaCha20.ContextLen];
			CryptoHChaCha20.DeriveSubkey(invalidKey, subKey, input, context);
		});
	}

	[Test]
	public void Throws_When_InputLengthInvalid()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoHChaCha20.KeyLen];
			Span<byte> subKey = stackalloc byte[CryptoHChaCha20.SubKeyLen];
			Span<byte> invalidInput = stackalloc byte[CryptoHChaCha20.InputLen - 1];
			Span<byte> context = stackalloc byte[CryptoHChaCha20.ContextLen];
			CryptoHChaCha20.DeriveSubkey(key, subKey, invalidInput, context);
		});
	}

	[Test]
	public void Throws_When_ContextLengthInvalid()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoHChaCha20.KeyLen];
			Span<byte> subKey = stackalloc byte[CryptoHChaCha20.SubKeyLen];
			Span<byte> input = stackalloc byte[CryptoHChaCha20.InputLen];
			Span<byte> invalidContext = stackalloc byte[CryptoHChaCha20.ContextLen - 1];
			CryptoHChaCha20.DeriveSubkey(key, subKey, input, invalidContext);
		});
	}

	[Test]
	public void DerivesDifferentKeys_When_InputDiffers()
	{
		Span<byte> key = stackalloc byte[CryptoHChaCha20.KeyLen];
		Span<byte> context = stackalloc byte[CryptoHChaCha20.ContextLen];
		Span<byte> input1 = stackalloc byte[CryptoHChaCha20.InputLen];
		Span<byte> input2 = stackalloc byte[CryptoHChaCha20.InputLen];

		Random.Shared.NextBytes(key);
		Random.Shared.NextBytes(context);
		Random.Shared.NextBytes(input1);
		Random.Shared.NextBytes(input2);
		while (input1.SequenceEqual(input2)) Random.Shared.NextBytes(input2);

		Span<byte> key1 = stackalloc byte[CryptoHChaCha20.SubKeyLen];
		Span<byte> key2 = stackalloc byte[CryptoHChaCha20.SubKeyLen];

		CryptoHChaCha20.DeriveSubkey(key, key1, input1, context);
		CryptoHChaCha20.DeriveSubkey(key, key2, input2, context);

		key1.ShouldNotBe(key2);
	}

	[Test]
	public void DerivesDifferentKeys_When_ContextDiffers()
	{
		Span<byte> key = stackalloc byte[CryptoHChaCha20.KeyLen];
		Span<byte> input = stackalloc byte[CryptoHChaCha20.InputLen];
		Span<byte> context1 = stackalloc byte[CryptoHChaCha20.ContextLen];
		Span<byte> context2 = stackalloc byte[CryptoHChaCha20.ContextLen];

		Random.Shared.NextBytes(key);
		Random.Shared.NextBytes(input);
		Random.Shared.NextBytes(context1);
		Random.Shared.NextBytes(context2);
		while (context1.SequenceEqual(context2)) Random.Shared.NextBytes(context2);


		Span<byte> key1 = stackalloc byte[CryptoHChaCha20.SubKeyLen];
		Span<byte> key2 = stackalloc byte[CryptoHChaCha20.SubKeyLen];

		CryptoHChaCha20.DeriveSubkey(key, key1, input, context1);
		CryptoHChaCha20.DeriveSubkey(key, key2, input, context2);

		key1.ShouldNotBe(key2);
	}

	[Test]
	public void AcceptsContextAsUtf8String()
	{
		Span<byte> key = stackalloc byte[CryptoHChaCha20.KeyLen];
		Span<byte> input = stackalloc byte[CryptoHChaCha20.InputLen];
		Span<byte> subKey = stackalloc byte[CryptoHChaCha20.SubKeyLen];

		Random.Shared.NextBytes(key);
		Random.Shared.NextBytes(input);

		CryptoHChaCha20.DeriveSubkey(key, subKey, input, "my-app/usage");

		subKey.ShouldNotBeZero();
	}

	[Test]
	public void DerivesSubkey_WithoutContext()
	{
		var key = new byte[CryptoHChaCha20.KeyLen];
		var input = new byte[CryptoHChaCha20.InputLen];

		Random.Shared.NextBytes(key);
		Random.Shared.NextBytes(input);

		Span<byte> subKey = stackalloc byte[CryptoHChaCha20.SubKeyLen];

		CryptoHChaCha20.DeriveSubkey(key, subKey, input);

		subKey.ShouldNotBeZero();
	}

	[Test]
	public void Throws_When_ContextStringTooLong()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoHChaCha20.KeyLen];
			Span<byte> input = stackalloc byte[CryptoHChaCha20.InputLen];
			Span<byte> subKey = stackalloc byte[CryptoHChaCha20.SubKeyLen];
			CryptoHChaCha20.DeriveSubkey(key, subKey, input, "this-context-string-is-too-long");
		});
	}

	[Test]

	public void DerivesDeterministicOutput_WithKnownVectors()
	{
		Span<byte> key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
		Span<byte> input = Convert.FromHexString("000000090000004A0000000000000000");
		var context = "expand 32-byte k";
		Span<byte> subkey = stackalloc byte[CryptoHChaCha20.SubKeyLen];

		CryptoHChaCha20.DeriveSubkey(key, subkey, input, context);

		var expected = Convert.FromHexString("4A4332AE7B2425F50B3A8E67BB58A22239FB04EEAE6E9F2094819C0DE6712C87");
		subkey.ShouldBe(expected);
	}

	[Test]
	public void NonceExtensionSample()
	{
// this is a sample to demonstrate nonce extension using HChaCha20
// it extends a 12-byte AES256-GCM nonce into a 28-byte nonce


Span<byte> key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

// 16 + 12 = 28 bytes total
Span<byte> extendedNonce = stackalloc byte[CryptoHChaCha20.InputLen + Aes256Gcm.NonceLen];
RandomGenerator.Fill(extendedNonce);

Span<byte> subkey = stackalloc byte[CryptoHChaCha20.SubKeyLen];

// first 16 bytes of nonce are used as input to derive the subkey
var input = extendedNonce.Slice(0, CryptoHChaCha20.InputLen);
CryptoHChaCha20.DeriveSubkey(key, subkey, input);

		
ReadOnlySpan<byte> plaintext = "some plaintext data to encrypt"u8;
Span<byte> ciphertext = stackalloc byte[plaintext.Length + Aes256Gcm.MacLen];
// the next 12 bytes of extended nonce are used as the AES256-GCM nonce
var nonce = extendedNonce.Slice(CryptoHChaCha20.InputLen, Aes256Gcm.NonceLen);

Aes256Gcm.Encrypt(ciphertext, plaintext, subkey, nonce: nonce);
	}
}