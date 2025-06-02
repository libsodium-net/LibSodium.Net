using System.Security.Cryptography;
using LibSodium.Tests;
using System.Text;

namespace LibSodium.Net.Tests;

public class CryptoHmacSha256Tests
{
	[Test]
	public void ComputeHash_ProducesSameOutputAsSystemHmacSha256()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha256.KeyLen];
		RandomGenerator.Fill(key);

		byte[] message = Encoding.UTF8.GetBytes("hello world");

		Span<byte> actualMac = stackalloc byte[CryptoHmacSha256.MacLen];
		CryptoHmacSha256.ComputeMac(key, message, actualMac);

		Span<byte> expectedMac = stackalloc byte[CryptoHmacSha256.MacLen];
		HMACSHA256.HashData(key, message, expectedMac);

		actualMac.ShouldBe(expectedMac);
	}

	[Test]
	public void VerifyHash_ReturnsTrueForCorrectMac()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("test message");
		Span<byte> actualMac = stackalloc byte[CryptoHmacSha256.MacLen];
		CryptoHmacSha256.ComputeMac(key, message, actualMac);

		bool valid = CryptoHmacSha256.VerifyMac(key, message, actualMac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void VerifyHash_ReturnsFalseForTamperedMac()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("test");
		Span<byte> actualMac = stackalloc byte[CryptoHmacSha256.MacLen];
		CryptoHmacSha256.ComputeMac(key, message, actualMac);
		actualMac[0] ^= 0xFF; // flip one bit

		bool valid = CryptoHmacSha256.VerifyMac(key, message, actualMac);
		valid.ShouldBeFalse();
	}

	[Test]
	public void GenerateKey_ProducesValidKey()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha256.KeyLen];
		CryptoHmacSha256.GenerateKey(key);

		key.ShouldNotBeZero();
	}

	[Test]
	public void ComputeHash_Stream_ProducesSameOutputAsSystem()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("stream message test");

		using var stream = new MemoryStream(message);
		Span<byte> actualMac = stackalloc byte[CryptoHmacSha256.MacLen];
		CryptoHmacSha256.ComputeMac(key, stream, actualMac);

		Span<byte> expectedMac = stackalloc byte[CryptoHmacSha256.MacLen];
		HMACSHA256.HashData(key, message, expectedMac);

		actualMac.ShouldBe(expectedMac);
	}

	[Test]
	public async Task ComputeHashAsync_Stream_ProducesSameOutputAsSystem()
	{
		var key = new byte[CryptoHmacSha256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("async stream message test");

		await using var stream = new MemoryStream(message);
		byte[] actualMac = new byte[CryptoHmacSha256.MacLen];
		await CryptoHmacSha256.ComputeMacAsync(key, stream, actualMac);

		var expectedMac = new byte[CryptoHmacSha256.MacLen];
		HMACSHA256.HashData(key, message, expectedMac);

		actualMac.ShouldBe(expectedMac);
	}

	[Test]
	public void VerifyHash_Stream_ReturnsTrueForCorrectMac()
	{
		Span<byte> key = stackalloc byte[CryptoHmacSha256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("verify stream test");

		Span<byte> expectedMac = stackalloc byte[CryptoHmacSha256.MacLen];
		using var forHash = new MemoryStream(message);
		CryptoHmacSha256.ComputeMac(key, forHash, expectedMac);

		using var forVerify = new MemoryStream(message);
		bool valid = CryptoHmacSha256.VerifyMac(key, forVerify, expectedMac);
		valid.ShouldBeTrue();
	}

	[Test]
	public async Task VerifyHashAsync_Stream_ReturnsTrueForCorrectMac()
	{
		byte[] key = new byte[CryptoHmacSha256.KeyLen];
		RandomGenerator.Fill(key);
		byte[] message = Encoding.UTF8.GetBytes("verify async stream test");

		byte[] expectedMac = new byte[CryptoHmacSha256.MacLen];
		await using var forHash = new MemoryStream(message);
		await CryptoHmacSha256.ComputeMacAsync(key, forHash, expectedMac);

		await using var forVerify = new MemoryStream(message);
		bool valid = await CryptoHmacSha256.VerifyMacAsync(key, forVerify, expectedMac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void ComputeHash_ThrowsIfKeyOrMacHasInvalidLength()
	{
		
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[3] { 1, 2, 3 };
			Span<byte> shortKey = stackalloc byte[CryptoHmacSha256.KeyLen - 1];
			Span<byte> mac = stackalloc byte[CryptoHmacSha256.MacLen];
			CryptoHmacSha256.ComputeMac(shortKey, message, mac);
		});
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[3] { 1, 2, 3 };
			Span<byte> longKey = stackalloc byte[CryptoHmacSha256.KeyLen + 1];
			Span<byte> mac = stackalloc byte[CryptoHmacSha256.MacLen];
			CryptoHmacSha256.ComputeMac(longKey, message, mac);
		});
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[3] { 1, 2, 3 };
			Span<byte> key = stackalloc byte[CryptoHmacSha256.KeyLen];
			Span<byte> shortMac = stackalloc byte[CryptoHmacSha256.MacLen - 1];
			CryptoHmacSha256.ComputeMac(key, message, shortMac);
		});
	}

	[Test]
	public void VerifyHash_ThrowsIfKeyOrMacHasInvalidLength()
	{
		
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[3];
			Span<byte> shortKey = stackalloc byte[CryptoHmacSha256.KeyLen - 1];
			Span<byte> mac = stackalloc byte[CryptoHmacSha256.MacLen];
			CryptoHmacSha256.VerifyMac(shortKey, message, mac);
		});
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> message = stackalloc byte[3];
			Span<byte> key = stackalloc byte[CryptoHmacSha256.KeyLen];
			Span<byte> shortMac = stackalloc byte[CryptoHmacSha256.MacLen - 1];
			CryptoHmacSha256.VerifyMac(key, message, shortMac);
		});
	}

	[Test]
	public void GenerateKey_ThrowsIfSpanHasInvalidLength()
	{
		AssertLite.Throws<ArgumentException>(() => {
			Span<byte> invalid = stackalloc byte[CryptoHmacSha256.KeyLen - 1];
			CryptoHmacSha256.GenerateKey(invalid);
		});
	}

	[Test]
	public void ComputeMac_WithSecureMemoryKey_ProducesSameMac()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha256.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("Hello with secure key");

		Span<byte> mac1 = stackalloc byte[CryptoHmacSha256.MacLen];
		CryptoHmacSha256.ComputeMac(key, message, mac1);

		Span<byte> mac2 = stackalloc byte[CryptoHmacSha256.MacLen];
		CryptoHmacSha256.ComputeMac(key.AsReadOnlySpan(), message, mac2);

		mac1.ShouldBe(mac2);
	}

	[Test]
	public void VerifyMac_WithSecureMemoryKey_ValidMac_ReturnsTrue()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha256.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("Secure verify message");

		Span<byte> mac = stackalloc byte[CryptoHmacSha256.MacLen];
		CryptoHmacSha256.ComputeMac(key, message, mac);

		bool valid = CryptoHmacSha256.VerifyMac(key, message, mac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void ComputeMac_Stream_WithSecureMemoryKey_ProducesSameMac()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha256.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("Stream with secure key");
		using var stream1 = new MemoryStream(message);
		using var stream2 = new MemoryStream(message);

		Span<byte> mac1 = stackalloc byte[CryptoHmacSha256.MacLen];
		CryptoHmacSha256.ComputeMac(key, stream1, mac1);

		Span<byte> mac2 = stackalloc byte[CryptoHmacSha256.MacLen];
		CryptoHmacSha256.ComputeMac(key.AsReadOnlySpan(), stream2, mac2);

		mac1.ShouldBe(mac2);
	}

	[Test]
	public async Task ComputeMacAsync_Stream_WithSecureMemoryKey_ProducesSameMac()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha256.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("Async stream secure test");

		await using var stream1 = new MemoryStream(message);
		await using var stream2 = new MemoryStream(message);

		var mac1 = new byte[CryptoHmacSha256.MacLen];
		await CryptoHmacSha256.ComputeMacAsync(key, stream1, mac1);

		var mac2 = new byte[CryptoHmacSha256.MacLen];
		await CryptoHmacSha256.ComputeMacAsync(key.AsReadOnlyMemory(), stream2, mac2);

		mac1.ShouldBe(mac2);
	}

	[Test]
	public void CreateIncrementalMac_WithSecureMemoryKey_ProducesSameResult()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha256.KeyLen);
		RandomGenerator.Fill(key);
		var part1 = Encoding.UTF8.GetBytes("chunk1");
		var part2 = Encoding.UTF8.GetBytes("chunk2");

		Span<byte> mac1 = stackalloc byte[CryptoHmacSha256.MacLen];
		using (var h = CryptoHmacSha256.CreateIncrementalMac(key))
		{
			h.Update(part1);
			h.Update(part2);
			h.Final(mac1);
		}

		Span<byte> mac2 = stackalloc byte[CryptoHmacSha256.MacLen];
		using (var h = CryptoHmacSha256.CreateIncrementalMac(key.AsReadOnlySpan()))
		{
			h.Update(part1);
			h.Update(part2);
			h.Final(mac2);
		}

		mac1.ShouldBe(mac2);
	}

	[Test]
	public async Task VerifyMacAsync_Stream_WithSecureMemoryKey_ReturnsTrue()
	{
		using var key = SecureMemory.Create<byte>(CryptoHmacSha256.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("secure verify async");

		var mac = new byte[CryptoHmacSha256.MacLen];
		await using var stream1 = new MemoryStream(message);
		await CryptoHmacSha256.ComputeMacAsync(key, stream1, mac);

		await using var stream2 = new MemoryStream(message);
		bool valid = await CryptoHmacSha256.VerifyMacAsync(key, stream2, mac);
		valid.ShouldBeTrue();
	}

}
