using LibSodium.Tests;
using System.Text;

namespace LibSodium.Net.Tests;

public class CryptoOneTimeAuthTests
{
	[Test]
	public void ComputeHash_ProducesValidMac()
	{
		Span<byte> key = stackalloc byte[CryptoOneTimeAuth.KeyLen];
		RandomGenerator.Fill(key);

		byte[] message = Encoding.UTF8.GetBytes("poly1305 test");

		Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];
		CryptoOneTimeAuth.ComputeMac(key, message, mac);

		mac.ShouldNotBeZero();
	}

	[Test]
	public void VerifyHash_ReturnsTrueForCorrectMac()
	{
		Span<byte> key = stackalloc byte[CryptoOneTimeAuth.KeyLen];
		RandomGenerator.Fill(key);

		byte[] message = Encoding.UTF8.GetBytes("auth check");
		Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];
		CryptoOneTimeAuth.ComputeMac(key, message, mac);

		bool valid = CryptoOneTimeAuth.VerifyMac(key, message, mac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void VerifyHash_ReturnsFalseForTamperedMac()
	{
		Span<byte> key = stackalloc byte[CryptoOneTimeAuth.KeyLen];
		RandomGenerator.Fill(key);

		byte[] message = Encoding.UTF8.GetBytes("tamper check");
		Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];
		CryptoOneTimeAuth.ComputeMac(key, message, mac);
		mac[0] ^= 0xFF;

		bool valid = CryptoOneTimeAuth.VerifyMac(key, message, mac);
		valid.ShouldBeFalse();
	}

	[Test]
	public void GenerateKey_ProducesValidKey()
	{
		Span<byte> key = stackalloc byte[CryptoOneTimeAuth.KeyLen];
		CryptoOneTimeAuth.GenerateKey(key);
		key.ShouldNotBeZero();
	}

	[Test]
	public void ComputeHash_Stream_Valid()
	{
		Span<byte> key = stackalloc byte[CryptoOneTimeAuth.KeyLen];
		RandomGenerator.Fill(key);

		byte[] message = Encoding.UTF8.GetBytes("stream test");
		using var stream = new MemoryStream(message);

		Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];
		CryptoOneTimeAuth.ComputeMac(key, stream, mac);

		mac.ShouldNotBeZero();
	}

	[Test]
	public async Task ComputeHashAsync_Stream_Valid()
	{
		byte[] key = new byte[CryptoOneTimeAuth.KeyLen];
		RandomGenerator.Fill(key);

		byte[] message = Encoding.UTF8.GetBytes("async stream test");
		await using var stream = new MemoryStream(message);

		byte[] mac = new byte[CryptoOneTimeAuth.MacLen];
		await CryptoOneTimeAuth.ComputeMacAsync(key, stream, mac);

		mac.ShouldNotBeZero();
	}

	[Test]
	public void VerifyHash_Stream_Valid()
	{
		Span<byte> key = stackalloc byte[CryptoOneTimeAuth.KeyLen];
		RandomGenerator.Fill(key);

		byte[] message = Encoding.UTF8.GetBytes("verify stream");
		Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];

		using var stream1 = new MemoryStream(message);
		CryptoOneTimeAuth.ComputeMac(key, stream1, mac);

		using var stream2 = new MemoryStream(message);
		bool valid = CryptoOneTimeAuth.VerifyMac(key, stream2, mac);
		valid.ShouldBeTrue();
	}

	[Test]
	public async Task VerifyHashAsync_Stream_Valid()
	{
		byte[] key = new byte[CryptoOneTimeAuth.KeyLen];
		RandomGenerator.Fill(key);

		byte[] message = Encoding.UTF8.GetBytes("async verify stream");
		byte[] mac = new byte[CryptoOneTimeAuth.MacLen];

		await using var stream1 = new MemoryStream(message);
		await CryptoOneTimeAuth.ComputeMacAsync(key, stream1, mac);

		await using var stream2 = new MemoryStream(message);
		bool valid = await CryptoOneTimeAuth.VerifyMacAsync(key, stream2, mac);

		valid.ShouldBeTrue();
	}

	[Test]
	public void ComputeHash_InvalidKeyOrMac_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoOneTimeAuth.KeyLen - 1];
			Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];
			Span<byte> msg = stackalloc byte[4];
			CryptoOneTimeAuth.ComputeMac(key, msg, mac);
		});

		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoOneTimeAuth.KeyLen];
			Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen - 1];
			Span<byte> msg = stackalloc byte[4];
			CryptoOneTimeAuth.ComputeMac(key, msg, mac);
		});
	}

	[Test]
	public void VerifyHash_InvalidKeyOrMac_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoOneTimeAuth.KeyLen - 1];
			Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];
			Span<byte> msg = stackalloc byte[4];
			CryptoOneTimeAuth.VerifyMac(key, msg, mac);
		});

		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoOneTimeAuth.KeyLen];
			Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen - 1];
			Span<byte> msg = stackalloc byte[4];
			CryptoOneTimeAuth.VerifyMac(key, msg, mac);
		});
	}

	[Test]
	public void GenerateKey_InvalidLength_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> buffer = stackalloc byte[CryptoOneTimeAuth.KeyLen - 1];
			CryptoOneTimeAuth.GenerateKey(buffer);
		});
	}

	[Test]
	public void GenerateKey_WithSecureMemory_Succeeds()
	{
		using var key = SecureMemory.Create<byte>(CryptoOneTimeAuth.KeyLen);
		CryptoOneTimeAuth.GenerateKey(key);
		key.AsSpan().ShouldNotBeZero();
	}

	[Test]
	public void ComputeMac_WithSecureMemoryKey_ProducesMac()
	{
		using var key = SecureMemory.Create<byte>(CryptoOneTimeAuth.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("Secure memory test");

		Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];
		CryptoOneTimeAuth.ComputeMac(key, message, mac);
		mac.ShouldNotBeZero();
	}

	[Test]
	public void VerifyMac_WithSecureMemoryKey_ReturnsTrue()
	{
		using var key = SecureMemory.Create<byte>(CryptoOneTimeAuth.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("Verify with secure key");

		Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];
		CryptoOneTimeAuth.ComputeMac(key, message, mac);
		bool valid = CryptoOneTimeAuth.VerifyMac(key, message, mac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void ComputeMac_Stream_WithSecureMemoryKey_ProducesMac()
	{
		using var key = SecureMemory.Create<byte>(CryptoOneTimeAuth.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("stream secure test");

		using var stream = new MemoryStream(message);
		Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];
		CryptoOneTimeAuth.ComputeMac(key, stream, mac);
		mac.ShouldNotBeZero();
	}

	[Test]
	public void VerifyMac_Stream_WithSecureMemoryKey_ReturnsTrue()
	{
		using var key = SecureMemory.Create<byte>(CryptoOneTimeAuth.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("verify stream secure");

		Span<byte> mac = stackalloc byte[CryptoOneTimeAuth.MacLen];
		using var stream1 = new MemoryStream(message);
		CryptoOneTimeAuth.ComputeMac(key, stream1, mac);

		using var stream2 = new MemoryStream(message);
		bool valid = CryptoOneTimeAuth.VerifyMac(key, stream2, mac);
		valid.ShouldBeTrue();
	}

	[Test]
	public async Task ComputeMacAsync_Stream_WithSecureMemoryKey_ProducesMac()
	{
		using var key = SecureMemory.Create<byte>(CryptoOneTimeAuth.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("async secure stream");

		await using var stream = new MemoryStream(message);
		var mac = new byte[CryptoOneTimeAuth.MacLen];
		await CryptoOneTimeAuth.ComputeMacAsync(key, stream, mac);
		mac.ShouldNotBeZero();
	}

	[Test]
	public async Task VerifyMacAsync_Stream_WithSecureMemoryKey_ReturnsTrue()
	{
		using var key = SecureMemory.Create<byte>(CryptoOneTimeAuth.KeyLen);
		RandomGenerator.Fill(key);
		var message = Encoding.UTF8.GetBytes("secure verify async");

		var mac = new byte[CryptoOneTimeAuth.MacLen];
		await using var stream1 = new MemoryStream(message);
		await CryptoOneTimeAuth.ComputeMacAsync(key, stream1, mac);

		await using var stream2 = new MemoryStream(message);
		bool valid = await CryptoOneTimeAuth.VerifyMacAsync(key, stream2, mac);
		valid.ShouldBeTrue();
	}

	[Test]
	public void CreateIncrementalMac_WithSecureMemoryKey_ProducesCorrectMac()
	{
		using var key = SecureMemory.Create<byte>(CryptoOneTimeAuth.KeyLen);
		RandomGenerator.Fill(key);
		var part1 = Encoding.UTF8.GetBytes("hello ");
		var part2 = Encoding.UTF8.GetBytes("secure world");

		Span<byte> mac1 = stackalloc byte[CryptoOneTimeAuth.MacLen];
		using (var h = CryptoOneTimeAuth.CreateIncrementalMac(key))
		{
			h.Update(part1);
			h.Update(part2);
			h.Final(mac1);
		}

		Span<byte> mac2 = stackalloc byte[CryptoOneTimeAuth.MacLen];
		using (var h = CryptoOneTimeAuth.CreateIncrementalMac(key.AsReadOnlySpan()))
		{
			h.Update(part1);
			h.Update(part2);
			h.Final(mac2);
		}

		mac1.ShouldBe(mac2);
	}



}
