using TUnit.Assertions.AssertConditions.Throws;

namespace LibSodium.Tests
{
	public class HexEncodingTests
	{
		static byte[] bin = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
		static string hex = "0123456789abcdef";

		[Test]
		public async Task BinToHex_ConvertsCorrectly()
		{
			string actualHex = HexEncoding.BinToHex(bin);
			await Assert.That(actualHex).IsEqualTo(hex);
		}

		[Test]
		public async Task BinToHex_EmptyBin_ReturnsEmptyString()
		{
			string actualHex = HexEncoding.BinToHex(Array.Empty<byte>());
			await Assert.That(actualHex).IsEqualTo(string.Empty);
		}

		[Test]
		public async Task BinToHex_Span_ConvertsCorrectly()
		{
			Span<char> hexBuffer = stackalloc char[bin.Length * 2];
			var actualHex = HexEncoding.BinToHex(bin, hexBuffer).ToString();
			await Assert.That(actualHex).IsEqualTo(hex);
		}

		[Test]
		public async Task BinToHex_Span_ThrowsArgumentException_WhenBufferTooSmall()
		{
			char[] hexBuffer = new char[bin.Length];
			await Assert.That(() => HexEncoding.BinToHex(bin, hexBuffer)).Throws<ArgumentException>();
		}

		[Test]
		public async Task HexToBin_ConvertsCorrectly()
		{
			Span<byte> binBuffer = stackalloc byte[hex.Length / 2];
			var binArray = HexEncoding.HexToBin(hex, binBuffer).ToArray();
			await Assert.That(binArray).IsSequenceEqualTo(bin);
		}

		[Test]
		public async Task HexToBin_EmptyHex_ReturnsEmptyBin()
		{
			string hex = string.Empty;
			var binSpan = HexEncoding.HexToBin(hex, Array.Empty<byte>());
			await Assert.That(binSpan.Length).IsEqualTo(0);
		}

		[Test]
		public async Task HexToBin_WithIgnore_ConvertsCorrectly()
		{
			string hex = "01:23:45:67:89:AB:CD:EF";
			Span<byte> binBuffer = stackalloc byte[8];
			var binArray = HexEncoding.HexToBin(hex, binBuffer, ":").ToArray();
			await Assert.That(binArray).IsSequenceEqualTo(bin);
		}

		[Test]
		public async Task HexToBin_ThrowsSodiumException_OnInvalidHex()
		{
			string invalidHex = "0123456789abcg"; // 'g' is an invalid hex character
			byte[] binBuffer = new byte[invalidHex.Length / 2];
			await Assert.That(() => HexEncoding.HexToBin(invalidHex, binBuffer)).Throws<SodioException>();
		}

		[Test]
		public async Task HexToBin_ThrowsSodiumException_OnBufferTooSmall()
		{
			byte[] binBuffer = new byte[1];
			await Assert.That(() => HexEncoding.HexToBin(hex, binBuffer)).Throws<SodioException>();
		}

		[Test]
		public async Task HexToBin_SpanChar_ConvertsCorrectly()
		{
			Span<byte> binBuffer = stackalloc byte[hex.Length / 2];
			var binArray = HexEncoding.HexToBin(hex.AsSpan(), binBuffer).ToArray();
			await Assert.That(binArray).IsSequenceEqualTo(bin);
		}

		[Test]
		public async Task HexToBin_SpanChar_EmptyHex_ReturnsEmptyBin()
		{
			var binSpanLen = HexEncoding.HexToBin(string.Empty.AsSpan(), Array.Empty<byte>()).Length;
			await Assert.That(binSpanLen).IsEqualTo(0);
		}
	}
}