using System.Security.Cryptography;
using LibSodium.Tests;
using System.Text;

namespace LibSodium.Net.Tests;

public class CryptoHmacSha512Tests
{
	[Test]
	public void ComputeHash_ProducesSameOutputAsSystemHmacSha512()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("hello world");

		Span<byte> actualMac = stackalloc byte[CryptoHmacSha512.MacLen];
		CryptoHmacSha512.ComputeMac(key, message, actualMac);

		Span<byte> expectedMac = stackalloc byte[CryptoHmacSha512.MacLen];
		HMACSHA512.HashData(key, message, expectedMac);

		actualMac.ShouldBe(expectedMac);
	}

	[Test]
	public void VerifyHash_ReturnsTrueForCorrectMac()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("test message");
		Span<byte> actualMac = stackalloc byte[CryptoHmacSha512.MacLen];
		CryptoHmacSha512.ComputeMac(key, message, actualMac);

		bool valid = CryptoHmacSha512.VerifyMac(key, message, actualMac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void VerifyHash_ReturnsFalseForTamperedMac()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("test");
		Span<byte> actualMac = stackalloc byte[CryptoHmacSha512.MacLen];
		CryptoHmacSha512.ComputeMac(key, message, actualMac);
		actualMac[0] ^= 0xFF;

		bool valid = CryptoHmacSha512.VerifyMac(key, message, actualMac);
		valid.ShouldBeFalse();
	}

	[Test]
	public void GenerateKey_ProducesValidKey()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512.KeyLen];
		CryptoHmacSha512.GenerateKey(key);
		key.ShouldNotBeZero();
	}

	[Test]
	public void ComputeHash_Stream_ProducesSameOutputAsSystem()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("stream message test");

		using var stream = new MemoryStream(message);
		Span<byte> actualMac = stackalloc byte[CryptoHmacSha512.MacLen];
		CryptoHmacSha512.ComputeMac(key, stream, actualMac);

		Span<byte> expectedMac = stackalloc byte[CryptoHmacSha512.MacLen];
		HMACSHA512.HashData(key, message, expectedMac);

		actualMac.ShouldBe(expectedMac);
	}

	[Test]
	public async Task ComputeHashAsync_Stream_ProducesSameOutputAsSystem()
	{
		byte[] key = new byte[CryptoHmacSha512.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("async stream message test");

		await using var stream = new MemoryStream(message);
		byte[] actualMac = new byte[CryptoHmacSha512.MacLen];
		await CryptoHmacSha512.ComputeMacAsync(key, stream, actualMac);

		var expectedMac = new byte[CryptoHmacSha512.MacLen];
		HMACSHA512.HashData(key, message, expectedMac);

		actualMac.ShouldBe(expectedMac);
	}

	[Test]
	public void VerifyHash_Stream_ReturnsTrueForCorrectMac()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha512.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("verify stream test");

		Span<byte> expectedMac = stackalloc byte[CryptoHmacSha512.MacLen];
		using var forHash = new MemoryStream(message);
		CryptoHmacSha512.ComputeMac(key, forHash, expectedMac);

		using var forVerify = new MemoryStream(message);
		bool valid = CryptoHmacSha512.VerifyMac(key, forVerify, expectedMac);
		valid.ShouldBeTrue();
	}

	[Test]
	public async Task VerifyHashAsync_Stream_ReturnsTrueForCorrectMac()
	{
		byte[] key = new byte[CryptoHmacSha512.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("verify async stream test");

		byte[] expectedMac = new byte[CryptoHmacSha512.MacLen];
		await using var forHash = new MemoryStream(message);
		await CryptoHmacSha512.ComputeMacAsync(key, forHash, expectedMac);

		await using var forVerify = new MemoryStream(message);
		bool valid = await CryptoHmacSha512.VerifyMacAsync(key, forVerify, expectedMac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void ComputeHash_ThrowsIfKeyOrMacHasInvalidLength()
	{
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[3];
			Span<byte> shortKey = stackalloc byte[CryptoHmacSha512.KeyLen - 1];
			Span<byte> mac = stackalloc byte[CryptoHmacSha512.MacLen];
			CryptoHmacSha512.ComputeMac(shortKey, message, mac);
		});
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[3];
			Span<byte> longKey = stackalloc byte[CryptoHmacSha512.KeyLen + 1];
			Span<byte> mac = stackalloc byte[CryptoHmacSha512.MacLen];
			CryptoHmacSha512.ComputeMac(longKey, message, mac);
		});
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[3];
			Span<byte> key = stackalloc byte[CryptoHmacSha512.KeyLen];
			Span<byte> shortMac = stackalloc byte[CryptoHmacSha512.MacLen - 1];
			CryptoHmacSha512.ComputeMac(key, message, shortMac);
		});
	}

	[Test]
	public void VerifyHash_ThrowsIfKeyOrMacHasInvalidLength()
	{
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[3];
			Span<byte> shortKey = stackalloc byte[CryptoHmacSha512.KeyLen - 1];
			Span<byte> mac = stackalloc byte[CryptoHmacSha512.MacLen];
			CryptoHmacSha512.VerifyMac(shortKey, message, mac);
		});
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[3];
			Span<byte> key = stackalloc byte[CryptoHmacSha512.KeyLen];
			Span<byte> shortMac = stackalloc byte[CryptoHmacSha512.MacLen - 1];
			CryptoHmacSha512.VerifyMac(key, message, shortMac);
		});
	}

	[Test]
	public void GenerateKey_ThrowsIfSpanHasInvalidLength()
	{
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> invalid = stackalloc byte[CryptoHmacSha512.KeyLen - 1];
			CryptoHmacSha512.GenerateKey(invalid);
		});
	}

	[Test]
	public void ComputeMac_WithSecureMemoryKey_ProducesSameMac()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha512.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("secure message");

		Span<byte> mac1 = stackalloc byte[CryptoHmacSha512.MacLen];
		CryptoHmacSha512.ComputeMac(key, message, mac1);

		Span<byte> mac2 = stackalloc byte[CryptoHmacSha512.MacLen];
		CryptoHmacSha512.ComputeMac(key.AsReadOnlySpan(), message, mac2);

		mac1.ShouldBe(mac2);
	}

	[Test]
	public void VerifyMac_WithSecureMemoryKey_ReturnsTrue()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha512.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("secure verify");

		Span<byte> mac = stackalloc byte[CryptoHmacSha512.MacLen];
		CryptoHmacSha512.ComputeMac(key, message, mac);

		bool valid = CryptoHmacSha512.VerifyMac(key, message, mac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void ComputeMac_Stream_WithSecureMemoryKey_ProducesSameMac()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha512.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("secure stream");

		using var stream1 = new MemoryStream(message);
		Span<byte> mac1 = stackalloc byte[CryptoHmacSha512.MacLen];
		CryptoHmacSha512.ComputeMac(key, stream1, mac1);

		using var stream2 = new MemoryStream(message);
		Span<byte> mac2 = stackalloc byte[CryptoHmacSha512.MacLen];
		CryptoHmacSha512.ComputeMac(key.AsReadOnlySpan(), stream2, mac2);

		mac1.ShouldBe(mac2);
	}

	[Test]
	public async Task ComputeMacAsync_Stream_WithSecureMemoryKey_ProducesSameMac()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha512.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("secure async stream");

		await using var stream1 = new MemoryStream(message);
		var mac1 = new byte[CryptoHmacSha512.MacLen];
		await CryptoHmacSha512.ComputeMacAsync(key, stream1, mac1);

		await using var stream2 = new MemoryStream(message);
		var mac2 = new byte[CryptoHmacSha512.MacLen];
		await CryptoHmacSha512.ComputeMacAsync(key.AsReadOnlyMemory(), stream2, mac2);

		mac1.ShouldBe(mac2);
	}

	[Test]
	public async Task VerifyMacAsync_Stream_WithSecureMemoryKey_ReturnsTrue()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha512.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("verify async secure");

		await using var stream1 = new MemoryStream(message);
		var mac = new byte[CryptoHmacSha512.MacLen];
		await CryptoHmacSha512.ComputeMacAsync(key, stream1, mac);

		await using var stream2 = new MemoryStream(message);
		bool valid = await CryptoHmacSha512.VerifyMacAsync(key, stream2, mac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void CreateIncrementalMac_WithSecureMemoryKey_ProducesSameResult()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha512.KeyLen);
		RandomGenerator.Fill(key);
		var part1 = Encoding.UTF8.GetBytes("part one");
		var part2 = Encoding.UTF8.GetBytes("part two");

		Span<byte> mac1 = stackalloc byte[CryptoHmacSha512.MacLen];
		using (var h = CryptoHmacSha512.CreateIncrementalMac(key))
		{
			h.Update(part1);
			h.Update(part2);
			h.Final(mac1);
		}

		Span<byte> mac2 = stackalloc byte[CryptoHmacSha512.MacLen];
		using (var h = CryptoHmacSha512.CreateIncrementalMac(key.AsReadOnlySpan()))
		{
			h.Update(part1);
			h.Update(part2);
			h.Final(mac2);
		}

		mac1.ShouldBe(mac2);
	}

}