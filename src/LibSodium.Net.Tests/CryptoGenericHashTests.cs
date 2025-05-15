using LibSodium.Tests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibSodium.Net.Tests
{
	public  class CryptoGenericHashTests
	{

		[Test]
		public void ComputeHash_WithMemoryStreamAndArray_ProducesSameHash()
		{
			var key = new byte[CryptoGenericHash.KeyLen];
			RandomGenerator.Fill(key);

			var message = Encoding.UTF8.GetBytes("Hello, LibSodium!");

			using var memoryStream = new MemoryStream(message);
			var hashFromStream = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hashFromStream, memoryStream, key);

			var hashFromArray = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hashFromArray, message, key);

			hashFromStream.ShouldBe(hashFromArray);
		}

		[Test]
		[Arguments(0)]
		[Arguments(1)]
		[Arguments(8191)]
		[Arguments(8192)]
		[Arguments(8193)]
		public void ComputeHash_WithMemoryStreamAndArray_VariousSizes_ProducesSameHash(int size)
		{
			var key = new byte[CryptoGenericHash.KeyLen];
			RandomGenerator.Fill(key);

			var message = new byte[size];
			Random.Shared.NextBytes(message);

			using var memoryStream = new MemoryStream(message);

			var hashFromStream = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hashFromStream, memoryStream, key);

			var hashFromArray = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hashFromArray, message, key);

			hashFromStream.ShouldBe(hashFromArray);
		}


		[Test]
		public void ComputeHash_WithDifferentKeys_ProducesDifferentHashes()
		{
			var key1 = new byte[CryptoGenericHash.KeyLen];
			var key2 = new byte[CryptoGenericHash.KeyLen];
			RandomGenerator.Fill(key1);
			RandomGenerator.Fill(key2);

			var message = Encoding.UTF8.GetBytes("Hello, LibSodium!");

			var hash1 = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hash1, message, key1);

			var hash2 = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hash2, message, key2);

			hash1.ShouldNotBe(hash2);
		}

		[Test]
		public async Task ComputeHashAsync_WithMemoryStreamAndArray_ProducesSameHashAsync()
		{
			var key = new byte[CryptoGenericHash.KeyLen];
			RandomGenerator.Fill(key);

			var message = Encoding.UTF8.GetBytes("Hello, LibSodium!");

			using var memoryStream = new MemoryStream(message);
			var hashFromStreamAsync = new byte[CryptoGenericHash.HashLen];
			await CryptoGenericHash.ComputeHashAsync(hashFromStreamAsync, memoryStream, key);

			var hashFromArray = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hashFromArray, message, key);

			hashFromStreamAsync.ShouldBe(hashFromArray);
		}

		[Test]
		public async Task ComputeHashAsync_WithCancellationToken_Success()
		{
			var key = new byte[CryptoGenericHash.KeyLen];
			RandomGenerator.Fill(key);

			var message = Encoding.UTF8.GetBytes("LibSodium async test!");

			using var memoryStream = new MemoryStream(message);
			var hashAsync = new byte[CryptoGenericHash.HashLen];

			var cts = new CancellationTokenSource();
			await CryptoGenericHash.ComputeHashAsync(hashAsync, memoryStream, key, cts.Token);

			var expectedHash = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(expectedHash, message, key);

			hashAsync.ShouldBe(expectedHash);
		}

		[Test]
		public void ComputeHash_EmptyMessage_EmptyKey_CorrectHash()
		{
			Span<byte> hash = stackalloc byte[32];
			CryptoGenericHash.ComputeHash(hash, Span<byte>.Empty, Span<byte>.Empty);
			var expected = Convert.FromHexString("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
			hash.ShouldBe(expected);
		}

		[Test]
		public void ComputeHash_ABCMessage_EmptyKey_CorrectHash()
		{
			var message = Encoding.UTF8.GetBytes("abc");
			Span<byte> hash = stackalloc byte[32];
			CryptoGenericHash.ComputeHash(hash, message, ReadOnlySpan<byte>.Empty);

			var expected = Convert.FromHexString("BDDD813C634239723171EF3FEE98579B94964E3BB1CB3E427262C8C068D52319");
			hash.ShouldBe(expected);
		}

		[Test]
		public void ComputeHash_HelloMessage_EmptyKey_CorrectHash()
		{
			var message = Encoding.UTF8.GetBytes("hello");
			Span<byte> hash = stackalloc byte[32];
			CryptoGenericHash.ComputeHash(hash, message, ReadOnlySpan<byte>.Empty);

			var expected = Convert.FromHexString("324DCF027DD4A30A932C441F365A25E86B173DEFA4B8E58948253471B81B72CF");
			hash.ShouldBe(expected);
		}

		[Test]
		public void ComputeHash512_EmptyMessage_EmptyKey_CorrectHash()
		{
			var message = Encoding.UTF8.GetBytes("");
			Span<byte> hash = stackalloc byte[64];
			CryptoGenericHash.ComputeHash(hash, message, ReadOnlySpan<byte>.Empty);

			var expected = Convert.FromHexString("786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE");
			hash.ToArray().ShouldBe(expected);
		}

		[Test]
		public void ComputeHash512_ABCMessage_EmptyKey_CorrectHash()
		{
			var message = Encoding.UTF8.GetBytes("abc");
			Span<byte> hash = stackalloc byte[64];
			CryptoGenericHash.ComputeHash(hash, message, ReadOnlySpan<byte>.Empty);

			var expected = Convert.FromHexString("BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923");
			hash.ToArray().ShouldBe(expected);
		}

		[Test]
		public void ComputeHash512_HelloMessage_EmptyKey_CorrectHash()
		{
			var message = Encoding.UTF8.GetBytes("hello");
			Span<byte> hash = stackalloc byte[64];
			CryptoGenericHash.ComputeHash(hash, message, ReadOnlySpan<byte>.Empty);

			var expected = Convert.FromHexString("E4CFA39A3D37BE31C59609E807970799CAA68A19BFAA15135F165085E01D41A65BA1E1B146AEB6BD0092B49EAC214C103CCFA3A365954BBBE52F74A2B3620C94");
			hash.ToArray().ShouldBe(expected);
		}
	}
}
