using System;
using System.Linq;

namespace LibSodium.Tests;

public class CryptoSignTests
{
	private const int MessageLen = 256;

	[Test]
	public void SignAndVerify_ShouldSucceed()
	{
		Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeyLen];
		Span<byte> privateKey = stackalloc byte[CryptoSign.PrivateKeyLen];
		CryptoSign.GenerateKeyPair(publicKey, privateKey);

		byte[] message = RandomBytes(MessageLen);
		Span<byte> signature = stackalloc byte[CryptoSign.SignatureLen];

		var actualSig = CryptoSign.Sign(message, signature, privateKey);
		actualSig.Length.ShouldBe(CryptoSign.SignatureLen);

		bool isValid = CryptoSign.TryVerify(message, actualSig, publicKey);
		isValid.ShouldBeTrue();
	}

	[Test]
	public void SignAndVerify_ShouldFail_OnTamperedMessage()
	{
		Span<byte> pk = stackalloc byte[CryptoSign.PublicKeyLen];
		Span<byte> sk = stackalloc byte[CryptoSign.PrivateKeyLen];
		CryptoSign.GenerateKeyPair(pk, sk);

		byte[] message = RandomBytes(MessageLen);
		Span<byte> signature = stackalloc byte[CryptoSign.SignatureLen];
		CryptoSign.Sign(message, signature, sk);

		message[0] ^= 1;

		CryptoSign.TryVerify(message, signature, pk).ShouldBeFalse();
	}

	[Test]
	public void SignAndVerify_ShouldThrow_OnInvalidSignature()
	{
		var pk = new byte[CryptoSign.PublicKeyLen];
		Span<byte> sk = stackalloc byte[CryptoSign.PrivateKeyLen];
		CryptoSign.GenerateKeyPair(pk, sk);

		byte[] message = RandomBytes(MessageLen);
		byte[] signature = RandomBytes(CryptoSign.SignatureLen);

		AssertLite.Throws<LibSodiumException>(() =>
			CryptoSign.Verify(message, signature, pk));
	}

	[Test]
	public void GenerateKeyPairDeterministically_ShouldBeDeterministic()
	{
		byte[] seed = RandomBytes(CryptoSign.SeedLen);

		Span<byte> pk1 = stackalloc byte[CryptoSign.PublicKeyLen];
		Span<byte> sk1 = stackalloc byte[CryptoSign.PrivateKeyLen];
		Span<byte> pk2 = stackalloc byte[CryptoSign.PublicKeyLen];
		Span<byte> sk2 = stackalloc byte[CryptoSign.PrivateKeyLen];

		CryptoSign.GenerateKeyPairDeterministically(pk1, sk1, seed);
		CryptoSign.GenerateKeyPairDeterministically(pk2, sk2, seed);

		pk1.ShouldBe(pk2);
		sk1.ShouldBe(sk2);
	}

	[Test]
	public void GenerateKeyPair_WithInvalidLengths_ShouldThrow()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> pk = stackalloc byte[CryptoSign.PublicKeyLen - 1];
			Span<byte> sk = stackalloc byte[CryptoSign.PrivateKeyLen];
			CryptoSign.GenerateKeyPair(pk, sk);
		});
	}

	[Test]
	public void GenerateKeyPairDeterministically_WithInvalidSeed_ShouldThrow()
	{


		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> pk = stackalloc byte[CryptoSign.PublicKeyLen];
			Span<byte> sk = stackalloc byte[CryptoSign.PrivateKeyLen];
			Span<byte> badSeed = stackalloc byte[CryptoSign.SeedLen - 1];
			CryptoSign.GenerateKeyPairDeterministically(pk, sk, badSeed);
		});
			
	}

	[Test]
	public void Sign_WithInvalidKeyLength_ShouldThrow()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			byte[] msg = RandomBytes(32);
			Span<byte> sig = stackalloc byte[CryptoSign.SignatureLen];
			byte[] badKey = new byte[CryptoSign.PrivateKeyLen - 1];
			CryptoSign.Sign(msg, sig, badKey);
		});
	}

	[Test]
	public void TryVerify_WithInvalidSignatureLength_ShouldThrow()
	{
		var pk = new byte[CryptoSign.PublicKeyLen];
		Span<byte> sk = stackalloc byte[CryptoSign.PrivateKeyLen];
		CryptoSign.GenerateKeyPair(pk, sk);

		byte[] msg = RandomBytes(64);
		byte[] badSig = new byte[CryptoSign.SignatureLen - 1];

		AssertLite.Throws<ArgumentException>(() =>
			CryptoSign.TryVerify(msg, badSig, pk));
	}

	[Test]
	public void TryVerify_WithInvalidPublicKeyLength_ShouldThrow()
	{
		var pk = new byte[CryptoSign.PublicKeyLen - 1];
		byte[] msg = RandomBytes(64);
		byte[] sig = RandomBytes(CryptoSign.SignatureLen);

		AssertLite.Throws<ArgumentException>(() =>
			CryptoSign.TryVerify(msg, sig, pk));
	}

	private static byte[] RandomBytes(int len)
	{
		var buf = new byte[len];
		Random.Shared.NextBytes(buf);
		return buf;
	}
}
