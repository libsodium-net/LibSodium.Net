using TUnit.Assertions.AssertConditions.Throws;

namespace LibSodium.Tests
{
	public class SecurePaddingTests
	{
		[Test]
		public void Pad_ShortData_PadsCorrectly()
		{
			Span<byte> buffer = stackalloc byte[] { 0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } ;
			var padded = SecurePadding.Pad(buffer, unpaddedLen: 3, blockSize: 8).ToArray();
			byte[] expected = { 0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00 };
			padded.ShouldBe(expected);
		}

		[Test]
		public void Pad_ExactBlockSize_PadsCorrectly()
		{
			Span<byte> buffer = stackalloc byte[] { 
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
			};

			var padded = SecurePadding.Pad(buffer, unpaddedLen: 8, blockSize: 8).ToArray();
			byte[] expected = { 
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
			};

			padded.ShouldBe(expected);

		}

		[Test]
		public void Pad_EmptyData_PadsCorrectly()
		{
			Span<byte> buffer = stackalloc byte[8];
			var padded = SecurePadding.Pad(buffer, unpaddedLen: 0, blockSize: 8).ToArray();
			byte[] expected = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			padded.ShouldBe(expected);
		}

		[Test]
		public void Unpad_PaddedData_UnpadsCorrectly()
		{
			Span<byte> padded = stackalloc byte[] { 0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00 };
			var unpadded = SecurePadding.Unpad(padded, blockSize: 8).ToArray();
			byte[] expected = { 0x01, 0x02, 0x03 };
			unpadded.ShouldBe(expected);
		}

		[Test]
		public void Unpad_ExactBlockSize_UnpadsCorrectly()
		{
			Span<byte> padded = stackalloc byte[] { 
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
			};
			var unpadded = SecurePadding.Unpad(padded, blockSize: 8).ToArray();

			byte[] expected = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
			unpadded.ShouldBe(expected);
		}

		[Test]
		public void Unpad_OnlyPadding_UnpadsCorrectly()
		{
			Span<byte> padded = stackalloc byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			var unpaddedLen = SecurePadding.Unpad(padded, blockSize: 8).Length;
			unpaddedLen.ShouldBe(0);
		}

		[Test]
		public void Unpad_InvalidPadding_ThrowsSodiumException()
		{
			byte[] invalidPadded1 = { 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Missing 0x80 marker
			byte[] invalidPadded2 = { 0x01, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01 }; // wrong padding value
			AssertLite.Throws<LibSodiumException>(() => SecurePadding.Unpad(invalidPadded1, blockSize: 8));
			AssertLite.Throws<LibSodiumException>(() => SecurePadding.Unpad(invalidPadded2, blockSize: 8));
		}

		[Test]
		public void Pad_ZeroBlockSize_ThrowsArgumentException()
		{
			byte[] buffer = { 0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
			AssertLite.Throws<ArgumentException>(() => SecurePadding.Pad(buffer, unpaddedLen: 3, blockSize: 0));
		}

		[Test]
		public void Pad_UnpaddedLenGreaterThanBufferLength_ThrowsArgumentException()
		{
			byte[] buffer = new byte[2];
			AssertLite.Throws<ArgumentException>(() => SecurePadding.Pad(buffer, unpaddedLen: 3, blockSize: 8));
		}
	}
}