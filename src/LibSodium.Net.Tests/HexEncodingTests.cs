using TUnit.Assertions.AssertConditions.Throws;

namespace LibSodium.Tests
{
	public class HexEncodingTests
	{
		static byte[] bin = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
		static string hex = "0123456789abcdef";

		[Test]
		public void BinToHex_ConvertsCorrectly()
		{
			string actualHex = HexEncoding.BinToHex(bin);
			actualHex.ShouldBe(hex);
		}

		[Test]
		public void BinToHex_EmptyBin_ReturnsEmptyString()
		{
			string actualHex = HexEncoding.BinToHex(Array.Empty<byte>());
			actualHex.ShouldBe(string.Empty);
		}

		[Test]
		public void BinToHex_Span_ConvertsCorrectly()
		{
			Span<char> hexBuffer = stackalloc char[bin.Length * 2];
			var actualHex = HexEncoding.BinToHex(bin, hexBuffer).ToString();
			actualHex.ShouldBe(hex);
		}

		[Test]
		public void BinToHex_Span_ThrowsArgumentException_WhenBufferTooSmall()
		{
			char[] hexBuffer = new char[bin.Length];
			AssertLite.Throws<ArgumentException>(() => HexEncoding.BinToHex(bin, hexBuffer));
		}

		[Test]
		public void HexToBin_ConvertsCorrectly()
		{
			Span<byte> binBuffer = stackalloc byte[hex.Length / 2];
			var binArray = HexEncoding.HexToBin(hex, binBuffer).ToArray();
			binArray.ShouldBe(bin);
		}

		[Test]
		public void HexToBin_EmptyHex_ReturnsEmptyBin()
		{
			string hex = string.Empty;
			var binSpan = HexEncoding.HexToBin(hex, Array.Empty<byte>());
			binSpan.Length.ShouldBe(0);
		}

		[Test]
		public void HexToBin_WithIgnore_ConvertsCorrectly()
		{
			string hex = "01:23:45:67:89:AB:CD:EF";
			Span<byte> binBuffer = stackalloc byte[8];
			var binArray = HexEncoding.HexToBin(hex, binBuffer, ":").ToArray();
			binArray.ShouldBe(bin);
		}

		[Test]
		public void HexToBin_ThrowsSodiumException_OnInvalidHex()
		{
			string invalidHex = "0123456789abcg"; // 'g' is an invalid hex character
			byte[] binBuffer = new byte[invalidHex.Length / 2];
			AssertLite.Throws<LibSodiumException>(() => HexEncoding.HexToBin(invalidHex, binBuffer));
		}

		[Test]
		public void HexToBin_ThrowsSodiumException_OnBufferTooSmall()
		{
			byte[] binBuffer = new byte[1];
			AssertLite.Throws<LibSodiumException>(() => HexEncoding.HexToBin(hex, binBuffer));
		}

		[Test]
		public void HexToBin_SpanChar_ConvertsCorrectly()
		{
			Span<byte> binBuffer = stackalloc byte[hex.Length / 2];
			var binSpan = HexEncoding.HexToBin(hex.AsSpan(), binBuffer);
			binSpan.ShouldBe(bin);
		}

		[Test]
		public void HexToBin_SpanChar_EmptyHex_ReturnsEmptyBin()
		{
			var binSpanLen = HexEncoding.HexToBin(string.Empty.AsSpan(), Array.Empty<byte>()).Length;
			binSpanLen.ShouldBe(0);
		}
	}
}