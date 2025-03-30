using TUnit.Assertions.AssertConditions.Throws;

namespace LibSodium.Tests
{
	public class SecurePaddingTests
	{
		[Test]
		public async Task Pad_ShortData_PadsCorrectly()
		{
			Span<byte> buffer = stackalloc byte[] { 0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } ;
			var padded = SecurePadding.Pad(buffer, unpaddedLen: 3, blockSize: 8).ToArray();
			byte[] expected = { 0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00 };
			await Assert.That(padded).IsSequenceEqualTo(expected);
		}

		[Test]
		public async Task Pad_ExactBlockSize_PadsCorrectly()
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

			await Assert.That(padded).IsSequenceEqualTo(expected);
		}

		[Test]
		public async Task Pad_EmptyData_PadsCorrectly()
		{
			Span<byte> buffer = stackalloc byte[8];
			var padded = SecurePadding.Pad(buffer, unpaddedLen: 0, blockSize: 8).ToArray();
			byte[] expected = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			await Assert.That(padded).IsSequenceEqualTo(expected);
		}

		[Test]
		public async Task Unpad_PaddedData_UnpadsCorrectly()
		{
			Span<byte> padded = stackalloc byte[] { 0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00 };
			var unpadded = SecurePadding.Unpad(padded, blockSize: 8).ToArray();
			byte[] expected = { 0x01, 0x02, 0x03 };
			await Assert.That(unpadded).IsSequenceEqualTo(expected);
		}

		[Test]
		public async Task Unpad_ExactBlockSize_UnpadsCorrectly()
		{
			Span<byte> padded = stackalloc byte[] { 
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
			};
			var unpadded = SecurePadding.Unpad(padded, blockSize: 8).ToArray();

			byte[] expected = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
			await Assert.That(unpadded).IsSequenceEqualTo(expected);
		}

		[Test]
		public async Task Unpad_OnlyPadding_UnpadsCorrectly()
		{
			Span<byte> padded = stackalloc byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			var unpaddedLen = SecurePadding.Unpad(padded, blockSize: 8).Length;
			await Assert.That(unpaddedLen).IsEqualTo(0);
		}

		[Test]
		public async Task Unpad_InvalidPadding_ThrowsSodiumException()
		{
			byte[] invalidPadded1 = { 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Missing 0x80 marker
			byte[] invalidPadded2 = { 0x01, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01 }; // wrong padding value
			await Assert.That(() => SecurePadding.Unpad(invalidPadded1, blockSize: 8)).Throws<LibSodiumException>();
			await Assert.That(() => SecurePadding.Unpad(invalidPadded2, blockSize: 8)).Throws<LibSodiumException>();
		}

		[Test]
		public async Task Pad_ZeroBlockSize_ThrowsArgumentException()
		{
			byte[] buffer = { 0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
			await Assert.That(() => SecurePadding.Pad(buffer, unpaddedLen:3, blockSize:0)).Throws<ArgumentException>();
		}

		[Test]
		public async Task Pad_UnpaddedLenGreaterThanBufferLength_ThrowsArgumentException()
		{
			byte[] buffer = new byte[2];
			await Assert.That(() => SecurePadding.Pad(buffer, unpaddedLen:3, blockSize: 8)).Throws<ArgumentException>();
		}
	}
}