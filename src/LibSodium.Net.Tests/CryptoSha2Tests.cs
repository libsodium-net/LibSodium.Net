using System.Security.Cryptography;
using LibSodium.Tests;

namespace LibSodium.Net.Tests;

public class CryptoSha2Tests
{
	// ── SHA‑256 ──────────────────────────────────────────────────────────────

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(17)]
	[Arguments(64)]
	[Arguments(1024)]
	public void ComputeHash256_Array_MatchesSystem(int size)
	{
		var message = new byte[size];
		RandomGenerator.Fill(message);

		Span<byte> hash = stackalloc byte[CryptoSha256.HashLen];
		CryptoSha256.ComputeHash(hash, message);

		var expected = SHA256.HashData(message);
		hash.ShouldBe(expected);
	}

	[Test]
	public void ComputeHash256_Stream_MatchesSystem()
	{
		var message = new byte[150_000];
		RandomGenerator.Fill(message);

		using var ms = new MemoryStream(message);
		Span<byte> hash = stackalloc byte[CryptoSha256.HashLen];
		CryptoSha256.ComputeHash(hash, ms);

		var expected = SHA256.HashData(message);
		hash.ShouldBe(expected);
	}

	[Test]
	public void ComputeHash256_InvalidHashBuffer_ShouldThrow()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> msg = stackalloc byte[1] { 0x01 };
			Span<byte> small = stackalloc byte[CryptoSha256.HashLen - 1];
			CryptoSha256.ComputeHash(small, msg);
		});
	}

	[Test]
	public void ComputeHash256_OversizedHashBuffer_ShouldThrow()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> msg = stackalloc byte[1] { 0x01 };
			Span<byte> large = stackalloc byte[CryptoSha256.HashLen + 1];
			CryptoSha256.ComputeHash(large, msg);
		});
	}

	[Test]
	public void ComputeHash256_NullStream_ShouldThrow()
	{
		AssertLite.Throws<ArgumentNullException>(() =>
		{
			Span<byte> hash = stackalloc byte[CryptoSha256.HashLen];
			Stream? s = null;
			CryptoSha256.ComputeHash(hash, s!);
		});
	}

	// ── SHA‑512 ──────────────────────────────────────────────────────────────

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(17)]
	[Arguments(64)]
	[Arguments(1024)]
	public void ComputeHash512_Array_MatchesSystem(int size)
	{
		var message = new byte[size];
		RandomGenerator.Fill(message);

		Span<byte> hash = stackalloc byte[CryptoSha512.HashLen];
		CryptoSha512.ComputeHash(hash, message);

		var expected = SHA512.HashData(message);
		hash.ShouldBe(expected);
	}

	[Test]
	public void ComputeHash512_Stream_MatchesSystem()
	{
		var message = new byte[150_000];
		RandomGenerator.Fill(message);

		using var ms = new MemoryStream(message);
		Span<byte> hash = stackalloc byte[CryptoSha512.HashLen];
		CryptoSha512.ComputeHash(hash, ms);

		var expected = SHA512.HashData(message);
		hash.ShouldBe(expected);
	}

	[Test]
	public void ComputeHash512_InvalidHashBuffer_ShouldThrow()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> msg = stackalloc byte[1] { 0x01 };
			Span<byte> small = stackalloc byte[CryptoSha512.HashLen - 1];
			CryptoSha512.ComputeHash(small, msg);
		});
	}

	[Test]
	public void ComputeHash512_OversizedHashBuffer_ShouldThrow()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> msg = stackalloc byte[1] { 0x01 };
			Span<byte> large = stackalloc byte[CryptoSha512.HashLen + 1];
			CryptoSha512.ComputeHash(large, msg);
		});
	}

	[Test]
	public void ComputeHash512_NullStream_ShouldThrow()
	{
		AssertLite.Throws<ArgumentNullException>(() =>
		{
			Span<byte> hash = stackalloc byte[CryptoSha512.HashLen];
			Stream? s = null;
			CryptoSha512.ComputeHash(hash, s!);
		});
	}
}
