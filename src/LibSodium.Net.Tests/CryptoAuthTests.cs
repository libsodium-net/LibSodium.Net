using Shouldly;
using TUnit;
using System;

namespace LibSodium.Tests;

public class CryptoAuthTests
{
	private static byte[] GenerateRandomBytes(int length)
	{
		var bytes = new byte[length];
		Random.Shared.NextBytes(bytes);
		return bytes;
	}

	[Test]
	public void GenerateKey_FillsKeyWithRandomBytes()
	{
		Span<byte> key = stackalloc byte[CryptoAuth.KeyLen];
		CryptoAuth.GenerateKey(key);
		SecureMemory.IsZero(key).ShouldBeFalse();
	}

	[Test]
	public void GenerateKey_ThrowsIfWrongLength()
	{
		Should.Throw<ArgumentException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoAuth.KeyLen - 1];
			CryptoAuth.GenerateKey(key);
		});

		Should.Throw<ArgumentException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoAuth.KeyLen + 1];
			CryptoAuth.GenerateKey(key);
		});
	}

	[Test]
	public void ComputeAndVerifyMac_Success()
	{
		Span<byte> key = stackalloc byte[CryptoAuth.KeyLen];
		Span<byte> mac = stackalloc byte[CryptoAuth.MacLen];
		Span<byte> message = stackalloc byte[32];
		RandomGenerator.Fill(message);

		CryptoAuth.GenerateKey(key);
		CryptoAuth.ComputeMac(mac, message, key);

		CryptoAuth.VerifyMac(mac, message, key);
		CryptoAuth.TryVerifyMac(mac, message, key).ShouldBeTrue();
	}

	[Test]
	public void VerifyMac_ReturnsFalse_IfMacIsInvalid()
	{
		Span<byte> key = stackalloc byte[CryptoAuth.KeyLen];
		Span<byte> mac = stackalloc byte[CryptoAuth.MacLen];
		Span<byte> message = stackalloc byte[32];
		RandomGenerator.Fill(message);

		CryptoAuth.GenerateKey(key);
		CryptoAuth.ComputeMac(mac, message, key);
		mac[0] ^= 0xFF;

		CryptoAuth.TryVerifyMac(mac, message, key).ShouldBeFalse();
	}

	[Test]
	public void VerifyMac_ThrowsLibSodiumException_WhenMacIsInvalid()
	{
		Should.Throw<LibSodiumException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoAuth.KeyLen];
			Span<byte> mac = stackalloc byte[CryptoAuth.MacLen];
			Span<byte> message = stackalloc byte[32];
			RandomGenerator.Fill(message);

			CryptoAuth.GenerateKey(key);
			CryptoAuth.ComputeMac(mac, message, key);
			mac[0] ^= 0xFF;
			CryptoAuth.VerifyMac(mac, message, key);
		});
	}

	[Test]
	public void ComputeMac_ThrowsArgumentException_IfBufferWrongSize()
	{
		Should.Throw<ArgumentException>(() =>
		{
			Span<byte> message = stackalloc byte[10];
			Span<byte> key = stackalloc byte[CryptoAuth.KeyLen];
			Span<byte> macTooSmall = stackalloc byte[CryptoAuth.MacLen - 1];
			CryptoAuth.ComputeMac(macTooSmall, message, key);
		});
	}

	[Test]
	public void ComputeMac_ThrowsArgumentException_IfKeyWrongSize()
	{
		Should.Throw<ArgumentException>(() =>
		{
			Span<byte> message = stackalloc byte[10];
			Span<byte> mac = stackalloc byte[CryptoAuth.MacLen];
			Span<byte> invalidKey = stackalloc byte[CryptoAuth.KeyLen - 1];
			CryptoAuth.ComputeMac(mac, message, invalidKey);
		});
	}
}
