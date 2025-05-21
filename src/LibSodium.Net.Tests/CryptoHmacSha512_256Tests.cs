using System.Security.Cryptography;
using LibSodium.Tests;
using System.Text;

namespace LibSodium.Net.Tests;

public class CryptoHmacSha512_256Tests
{
	[Test]
	public void ComputeHash_ProducesSameOutputAsSystemHmacSha512Truncated()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512_256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("hello world");

		Span<byte> actualMac = stackalloc byte[CryptoHmacSha512_256.MacLen];
		CryptoHmacSha512_256.ComputeMac(key, message, actualMac);

		Span<byte> expectedMac = stackalloc byte[CryptoHmacSha512.MacLen];
		HMACSHA512.HashData(key, message, expectedMac);
		expectedMac = expectedMac.Slice(0, CryptoHmacSha512_256.MacLen);

		actualMac.ShouldBe(expectedMac);
	}

	[Test]
	public void VerifyHash_ReturnsTrueForCorrectMac()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512_256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("test message");
		Span<byte> actualMac = stackalloc byte[CryptoHmacSha512_256.MacLen];
		CryptoHmacSha512_256.ComputeMac(key, message, actualMac);

		bool valid = CryptoHmacSha512_256.VerifyMac(key, message, actualMac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void VerifyHash_ReturnsFalseForTamperedMac()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512_256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("test");
		Span<byte> actualMac = stackalloc byte[CryptoHmacSha512_256.MacLen];
		CryptoHmacSha512_256.ComputeMac(key, message, actualMac);
		actualMac[0] ^= 0xFF;

		bool valid = CryptoHmacSha512_256.VerifyMac(key, message, actualMac);
		valid.ShouldBeFalse();
	}

	[Test]
	public void GenerateKey_ProducesValidKey()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512_256.KeyLen];
		CryptoHmacSha512_256.GenerateKey(key);
		key.ShouldNotBeZero();
	}

	[Test]
	public void ComputeHash_Stream_ProducesSameOutputAsSystemTruncated()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512_256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("stream message test");

		using var stream = new MemoryStream(message);
		Span<byte> actualMac = stackalloc byte[CryptoHmacSha512_256.MacLen];
		CryptoHmacSha512_256.ComputeMac(key, stream, actualMac);

		Span<byte> expectedMac = stackalloc byte[CryptoHmacSha512.MacLen];
		HMACSHA512.HashData(key, message, expectedMac);
		expectedMac = expectedMac.Slice(0, CryptoHmacSha512_256.MacLen);

		actualMac.ShouldBe(expectedMac);
	}

	[Test]
	public async Task ComputeHashAsync_Stream_ProducesSameOutputAsSystemTruncated()
	{
		byte[] key = new byte[CryptoHmacSha512_256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("async stream message test");

		await using var stream = new MemoryStream(message);
		byte[] actualMac = new byte[CryptoHmacSha512_256.MacLen];
		await CryptoHmacSha512_256.ComputeMacAsync(key, stream, actualMac);

		var expectedMac = new byte[CryptoHmacSha512.MacLen];
		HMACSHA512.HashData(key, message, expectedMac);
		expectedMac = expectedMac[..CryptoHmacSha512_256.MacLen];

		actualMac.ShouldBe(expectedMac);
	}

	[Test]
	public void ComputeHash_ThrowsIfKeyOrMacHasInvalidLength()
	{
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[1];
			Span<byte> shortKey = stackalloc byte[CryptoHmacSha512_256.KeyLen - 1];
			Span<byte> mac = stackalloc byte[CryptoHmacSha512_256.MacLen];
			CryptoHmacSha512_256.ComputeMac(shortKey, message, mac);
		});
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[1];
			Span<byte> longKey = stackalloc byte[CryptoHmacSha512_256.KeyLen + 1];
			Span<byte> mac = stackalloc byte[CryptoHmacSha512_256.MacLen];
			CryptoHmacSha512_256.ComputeMac(longKey, message, mac);
		});
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[1];
			Span<byte> key = stackalloc byte[CryptoHmacSha512_256.KeyLen];
			Span<byte> shortMac = stackalloc byte[CryptoHmacSha512_256.MacLen - 1];
			CryptoHmacSha512_256.ComputeMac(key, message, shortMac);
		});
	}

	[Test]
	public void VerifyHash_ThrowsIfKeyOrMacHasInvalidLength()
	{
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[1];
			Span<byte> shortKey = stackalloc byte[CryptoHmacSha512_256.KeyLen - 1];
			Span<byte> mac = stackalloc byte[CryptoHmacSha512_256.MacLen];
			CryptoHmacSha512_256.VerifyMac(shortKey, message, mac);
		});
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[1];
			Span<byte> key = stackalloc byte[CryptoHmacSha512_256.KeyLen];
			Span<byte> shortMac = stackalloc byte[CryptoHmacSha512_256.MacLen - 1];
			CryptoHmacSha512_256.VerifyMac(key, message, shortMac);
		});
	}

	[Test]
	public void GenerateKey_ThrowsIfSpanHasInvalidLength()
	{
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> invalid = stackalloc byte[CryptoHmacSha512_256.KeyLen - 1];
			CryptoHmacSha512_256.GenerateKey(invalid);
		});
	}

	[Test]
	public void VerifyHash_Stream_ReturnsTrueForCorrectMac()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512_256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("verify stream test");

		Span<byte> expectedMac = stackalloc byte[CryptoHmacSha512_256.MacLen];
		using var forHash = new MemoryStream(message);
		CryptoHmacSha512_256.ComputeMac(key, forHash, expectedMac);

		using var forVerify = new MemoryStream(message);
		bool valid = CryptoHmacSha512_256.VerifyMac(key, forVerify, expectedMac);
		valid.ShouldBeTrue();
	}

	[Test]
	public async Task VerifyHashAsync_Stream_ReturnsTrueForCorrectMac()
	{
		byte[] key = new byte[CryptoHmacSha512_256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("verify async stream test");

		byte[] expectedMac = new byte[CryptoHmacSha512_256.MacLen];
		using var forHash = new MemoryStream(message);
		await CryptoHmacSha512_256.ComputeMacAsync(key, forHash, expectedMac);

		using var forVerify = new MemoryStream(message);
		bool valid = await CryptoHmacSha512_256.VerifyMacAsync(key, forVerify, expectedMac);
		valid.ShouldBeTrue();
	}
}
