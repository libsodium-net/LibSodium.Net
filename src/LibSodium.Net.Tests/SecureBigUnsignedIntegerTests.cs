using TUnit.Assertions.AssertConditions.Throws;

namespace LibSodium.Tests
{
	public class SecureBigUnsignedIntegerTests
	{
		[Test]
		public void Equals_EqualBuffers_ReturnsTrue()
		{
			byte[] b1 = { 1, 2, 3, 4 };
			byte[] b2 = { 1, 2, 3, 4 };
			SecureBigUnsignedInteger.Equals(b1, b2).ShouldBeTrue();
		}

		[Test]
		public void Equals_DifferentBuffers_ReturnsFalse()
		{
			byte[] b1 = { 1, 2, 3, 4 };
			byte[] b2 = { 4, 3, 2, 1 };
			SecureBigUnsignedInteger.Equals(b1, b2).ShouldBeFalse();
		}

		[Test]
		public void Equals_DifferentLengths_ReturnsFalse()
		{
			byte[] b1 = { 1, 2, 3, 4 };
			byte[] b2 = { 1, 2, 3 };

			SecureBigUnsignedInteger.Equals(b1, b2).ShouldBeFalse();
		}

		[Test]
		public void Increment_IncrementsByOne()
		{
			byte[] number = { 0, 0, 0, 0 };
			byte[] expected = { 1, 0, 0, 0 };

			SecureBigUnsignedInteger.Increment(number);
			number.ShouldBe(expected);
		}

		[Test]
		public void Increment_IncrementsByValue()
		{
			byte[] number = { 0, 0, 0, 0, 0, 0, 0, 0 };
			byte[] expected = { 1, 0, 0, 0, 0, 0, 0, 0 };

			SecureBigUnsignedInteger.Increment(number, 1);
			number.ShouldBe(expected);
		}

		[Test]
		public void Increment_IncrementsByLargeValue()
		{
			byte[] number = { 0, 0, 0, 0, 0, 0, 0, 0 };
			byte[] expected = { 255, 255, 255, 255, 255, 255, 255, 127 };

			SecureBigUnsignedInteger.Increment(number, long.MaxValue);
			number.ShouldBe(expected);
		}

		[Test]
		public void Add_AddsTwoBuffers()
		{
			byte[] a = { 1, 0, 0, 0 };
			byte[] b = { 1, 0, 0, 0 };
			byte[] expected = { 2, 0, 0, 0 };

			SecureBigUnsignedInteger.Add(a, b);
			a.ShouldBe(expected);
		}

		[Test]
		public void Add_DifferentLengths_ThrowsArgumentException()
		{
			byte[] a = { 1, 0, 0, 0 };
			byte[] b = { 1, 0, 0 };

			AssertLite.Throws<ArgumentException>(() => SecureBigUnsignedInteger.Add(a, b));
		}

		[Test]
		public void Subtract_SubtractsTwoBuffers()
		{
			byte[] subtrahend = { 2, 0, 0, 0 };
			byte[] minuend = { 1, 0, 0, 0 };
			byte[] expected = { 1, 0, 0, 0 };

			SecureBigUnsignedInteger.Subtract(subtrahend, minuend);
			subtrahend.ShouldBe(expected);
		}

		[Test]
		public void Subtract_DifferentLengths_ThrowsArgumentException()
		{
			byte[] subtrahend = { 2, 0, 0, 0 };
			byte[] minuend = { 1, 0, 0 };

			AssertLite.Throws<ArgumentException>(() => SecureBigUnsignedInteger.Subtract(subtrahend, minuend));
		}

		[Test]
		public void Compare_EqualBuffers_ReturnsZero()
		{
			byte[] b1 = { 1, 2, 3, 4 };
			byte[] b2 = { 1, 2, 3, 4 };
			SecureBigUnsignedInteger.Compare(b1, b2).ShouldBe(0);
		}

		[Test]
		public void Compare_FirstBufferLess_ReturnsMinusOne()
		{
			byte[] b1 = { 4, 3, 2, 1 };
			byte[] b2 = { 1, 2, 3, 4 };
			SecureBigUnsignedInteger.Compare(b1, b2).ShouldBe(-1);
		}

		[Test]
		public void Compare_FirstBufferGreater_ReturnsOne()
		{
			byte[] b1 = { 1, 2, 3, 4 };
			byte[] b2 = { 4, 3, 2, 1 };
			SecureBigUnsignedInteger.Compare(b1, b2).ShouldBe(1);
		}

		[Test]
		public void Compare_DifferentLengths_ThrowsArgumentException()
		{
			byte[] b1 = { 1, 2, 3, 4 };
			byte[] b2 = { 1, 2, 3 };

			AssertLite.Throws<ArgumentException>(() => SecureBigUnsignedInteger.Compare(b1, b2));
		}

		[Test]
		public void IsZero_ZeroBuffer_ReturnsTrue()
		{
			byte[] b = { 0, 0, 0, 0 };
			SecureBigUnsignedInteger.IsZero(b).ShouldBeTrue();
		}

		[Test]
		public void IsZero_NonZeroBuffer_ReturnsFalse()
		{
			byte[] b = { 1, 0, 0, 0 };
			SecureBigUnsignedInteger.IsZero(b).ShouldBeFalse();
		}
	}
}