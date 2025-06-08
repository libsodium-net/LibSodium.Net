using System.Diagnostics;
using System.Security.Cryptography;
using TUnit;
using static LibSodium.CryptoScalarMult;

namespace LibSodium.Tests;

public class CryptoScalarMultTests
{
	[Test]
	public void CalculatePublicKey_DifferentInputs_ProduceDifferentOutputs()
	{
		Span<byte> privateKey1 = stackalloc byte[PrivateKeyLen];
		Span<byte> privateKey2 = stackalloc byte[PrivateKeyLen];
		Span<byte> publicKey1 = stackalloc byte[PublicKeyLen];
		Span<byte> publicKey2 = stackalloc byte[PublicKeyLen];

		RandomGenerator.Fill(privateKey1);
		RandomGenerator.Fill(privateKey2);

		CalculatePublicKey(publicKey1, privateKey1);
		CalculatePublicKey(publicKey2, privateKey2);

		publicKey1.ShouldNotBe(publicKey2);
	}

	[Test]
	public void CalculatePublicKey_InvalidLengths_Throw()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> pub = stackalloc byte[PublicKeyLen - 1];
			Span<byte> priv = stackalloc byte[PrivateKeyLen];
			CalculatePublicKey(pub, priv);
		});

		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> pub = stackalloc byte[PublicKeyLen];
			Span<byte> priv = stackalloc byte[PrivateKeyLen - 1];
			CalculatePublicKey(pub, priv);
		});
	}

	[Test]
	public void Compute_SharedKey_MatchesOnBothSides()
	{
		Span<byte> alicePriv = stackalloc byte[PrivateKeyLen];
		Span<byte> bobPriv = stackalloc byte[PrivateKeyLen];
		Span<byte> alicePub = stackalloc byte[PublicKeyLen];
		Span<byte> bobPub = stackalloc byte[PublicKeyLen];
		Span<byte> shared1 = stackalloc byte[PublicKeyLen];
		Span<byte> shared2 = stackalloc byte[PublicKeyLen];

		RandomGenerator.Fill(alicePriv);
		RandomGenerator.Fill(bobPriv);
		CalculatePublicKey(alicePub, alicePriv);
		CalculatePublicKey(bobPub, bobPriv);

		Compute(shared1, alicePriv, bobPub);
		Compute(shared2, bobPriv, alicePub);

		shared1.ShouldBe(shared2);
	}

	[Test]
	public void Compute_InvalidLengths_Throw()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> output = stackalloc byte[PublicKeyLen - 1];
			Span<byte> priv = stackalloc byte[PrivateKeyLen];
			Span<byte> pub = stackalloc byte[PublicKeyLen];
			Compute(output, priv, pub);
		});

		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> output = stackalloc byte[PublicKeyLen];
			Span<byte> priv = stackalloc byte[PrivateKeyLen - 1];
			Span<byte> pub = stackalloc byte[PublicKeyLen];
			Compute(output, priv, pub);
		});

		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> output = stackalloc byte[PublicKeyLen];
			Span<byte> priv = stackalloc byte[PrivateKeyLen];
			Span<byte> pub = stackalloc byte[PublicKeyLen - 1];
			Compute(output, priv, pub);
		});
	}

	[Test]
	public void CalculatePublicKey_ZeroPrivateKey_YieldsExpectedPublicKey()
	{
		Span<byte> privateKey = stackalloc byte[PrivateKeyLen]; // all zero
		Span<byte> publicKey = stackalloc byte[PublicKeyLen];

		CalculatePublicKey(publicKey, privateKey);

		Span<byte> expectedPublicKey = stackalloc byte[PublicKeyLen];
		HexEncoding.HexToBin("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74", expectedPublicKey);

		publicKey.ShouldBe(expectedPublicKey);
	}

	[Test]
	public void Compute_ZeroPrivateAndPublicKey_ThrowsLibsodiumException()
	{
		AssertLite.Throws<LibSodiumException>(() =>
		{
			Span<byte> privateKey = stackalloc byte[PrivateKeyLen]; // all zero
			Span<byte> publicKey = stackalloc byte[PublicKeyLen]; // all zero
			Span<byte> sharedKey = stackalloc byte[PublicKeyLen];
			Compute(sharedKey, privateKey, publicKey);
		});

	}

	[Test]
	public void CalculatePublicKey_WithSecureMemoryPrivateKey_Succeeds()
	{
		using var privateKey = SecureMemory.Create<byte>(PrivateKeyLen);
		Span<byte> publicKey1 = stackalloc byte[PublicKeyLen];
		Span<byte> publicKey2 = stackalloc byte[PublicKeyLen];
		RandomGenerator.Fill(privateKey);

		CalculatePublicKey(publicKey1, privateKey);
		CalculatePublicKey(publicKey2, privateKey.AsReadOnlySpan());

		publicKey1.ShouldBe(publicKey2);
	}

	[Test]
	public void Compute_WithSecureMemoryPrivateKey_Succeeds()
	{
		using var alicePriv = SecureMemory.Create<byte>(PrivateKeyLen);
		using var bobPriv = SecureMemory.Create<byte>(PrivateKeyLen);
		Span<byte> alicePub = stackalloc byte[PublicKeyLen];
		Span<byte> bobPub = stackalloc byte[PublicKeyLen];
		using var shared1 = new SecureMemory<byte>(PublicKeyLen);
		using var shared2 = new SecureMemory<byte>(PublicKeyLen);

		RandomGenerator.Fill(alicePriv);
		RandomGenerator.Fill(bobPriv);

		CalculatePublicKey(alicePub, alicePriv);
		CalculatePublicKey(bobPub, bobPriv);

		Compute(shared1, alicePriv, bobPub);
		Compute(shared2, bobPriv, alicePub);

		shared1.ShouldBe(shared2);
	}

	[Test]
	public void Compute_WithSecureMemoryInvalidLength_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			using var priv = SecureMemory.Create<byte>(PrivateKeyLen - 1);
			Span<byte> pub = stackalloc byte[PublicKeyLen];
			using var shared = new SecureMemory<byte>(PublicKeyLen);
			Compute(shared, priv, pub);
		});
	}

	[Test]
	public void CalculatePublicKey_WithZeroSecureMemoryInput_YieldsExpectedResult()
	{
		using var priv = SecureMemory.Create<byte>(PrivateKeyLen);
		priv.MemZero();
		Span<byte> pub = stackalloc byte[PublicKeyLen];
		CalculatePublicKey(pub, priv);

		Span<byte> expected = stackalloc byte[PublicKeyLen];
		HexEncoding.HexToBin("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74", expected);
		pub.ShouldBe(expected);
	}

	[Test]
	public void ComputeSharedKeyExample()
	{
using var alicePrivateKey = new SecureMemory<byte>(CryptoScalarMult.PrivateKeyLen);
Span<byte> alicePublicKey = stackalloc byte[CryptoScalarMult.PublicKeyLen];
RandomGenerator.Fill(alicePrivateKey);
CryptoScalarMult.CalculatePublicKey(alicePublicKey, alicePrivateKey);


using var bobPrivateKey = new SecureMemory<byte>(CryptoScalarMult.PrivateKeyLen);
Span<byte> bobPublicKey = stackalloc byte[CryptoScalarMult.PublicKeyLen];
RandomGenerator.Fill(bobPrivateKey);
CryptoScalarMult.CalculatePublicKey(bobPublicKey, bobPrivateKey);

using var aliceSharedSecret = new SecureMemory<byte>(CryptoScalarMult.PublicKeyLen);
CryptoScalarMult.Compute(aliceSharedSecret, alicePrivateKey, bobPublicKey);

using var bobSharedSecret = new SecureMemory<byte>(CryptoScalarMult.PublicKeyLen);
CryptoScalarMult.Compute(bobSharedSecret, bobPrivateKey, alicePublicKey);

bool isTheSameSharedSecret = aliceSharedSecret.AsReadOnlySpan().SequenceEqual(bobSharedSecret.AsReadOnlySpan());

Debug.Assert(isTheSameSharedSecret, "Shared secrets should match between Alice and Bob.");

using var aliceTxKey = new SecureMemory<byte>(XChaCha20Poly1305.KeyLen);
CryptoHkdf.DeriveKey(HashAlgorithmName.SHA512, ikm: aliceSharedSecret, okm: aliceTxKey, 
	salt: alicePublicKey, info: bobPublicKey);

using var bobRxKey = new SecureMemory<byte>(XChaCha20Poly1305.KeyLen);
CryptoHkdf.DeriveKey(HashAlgorithmName.SHA512, ikm: bobSharedSecret, okm: bobRxKey, 
	salt: alicePublicKey, info: bobPublicKey);

bool isTheSameTxRxKey = aliceTxKey.AsReadOnlySpan().SequenceEqual(bobRxKey.AsReadOnlySpan());

Debug.Assert(isTheSameTxRxKey, "Transmission key derived by Alice should match receive key derived by Bob.");

	}

}
