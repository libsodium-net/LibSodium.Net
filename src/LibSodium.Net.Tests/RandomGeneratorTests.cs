using TUnit.Assertions.AssertConditions.Throws;

namespace LibSodium.Tests
{
	public class RandomGeneratorTests
	{
		[Test]
		public void GetUInt32_ReturnsRandomUInt32()
		{
			uint random1 = RandomGenerator.GetUInt32();
			uint random2 = RandomGenerator.GetUInt32();
			random1.ShouldNotBe(random2);
		}

		[Test]
		public void GetUInt32_WithUpperBound_ReturnsRandomUInt32LessThanUpperBound()
		{
			uint upperBound = 100;
			uint random = RandomGenerator.GetUInt32(upperBound);
			random.ShouldBeLessThan(upperBound);
		}

		[Test]
		public void Fill_FillsBufferWithRandomBytes()
		{
			var b1 = new byte[10];
			var b2 = new byte[10];

			RandomGenerator.Fill(b1);
			RandomGenerator.Fill(b2);

			b1.ShouldNotBe(b2);
			b1.ShouldNotBeZero();
			b2.ShouldNotBeZero();
		}


		[Test]
		public void Fill_Fills_SecureMemory_Buffer_With_RandomBytes()
		{
			using var b1 = SecureMemory.Create<byte>(10);
			using var b2 = SecureMemory.Create<byte>(10);

			RandomGenerator.Fill(b1);
			RandomGenerator.Fill(b2);

			b1.AsSpan().ShouldNotBe(b2.AsSpan());
			b1.AsSpan().ShouldNotBeZero();
			b2.AsSpan().ShouldNotBeZero();
		}

		[Test]
		public void FillDeterministic_FillsBufferWithDeterministicRandomBytes()
		{
			Span<byte> s1 = stackalloc byte[RandomGenerator.SeedLen];
			Span<byte> s2 = stackalloc byte[RandomGenerator.SeedLen];

			Random.Shared.NextBytes(s1);
			Random.Shared.NextBytes(s2);

			var b1s1 = new byte[32];
			var b2s1 = new byte[32];
			var b3s2 = new byte[32];

			RandomGenerator.FillDeterministic(b1s1, s1);
			RandomGenerator.FillDeterministic(b2s1, s1);
			RandomGenerator.FillDeterministic(b3s2, s2);

			b1s1.ShouldBe(b2s1);
			b1s1.ShouldNotBe(b3s2);
		}


		[Test]
		public void FillDeterministic_Fills_SecureMemory_Buffer_With_Deterministic_RandomBytes()
		{
			using var s1 = SecureMemory.Create<byte>(RandomGenerator.SeedLen);
			using var s2 = SecureMemory.Create<byte>(RandomGenerator.SeedLen);
			
			Random.Shared.NextBytes(s1.AsSpan());
			Random.Shared.NextBytes(s2.AsSpan());

			using var b1s1 = SecureMemory.Create<byte>(32);
			using var b2s1 = SecureMemory.Create<byte>(32);
			using var b3s2 = SecureMemory.Create<byte>(32);

			RandomGenerator.FillDeterministic(b1s1, s1);
			RandomGenerator.FillDeterministic(b2s1, s1);
			RandomGenerator.FillDeterministic(b3s2, s2);

			b1s1.AsSpan().ShouldBe(b2s1.AsSpan());
			b1s1.AsSpan().ShouldNotBe(b3s2.AsSpan());
		}

		[Test]
		public void FillDeterministic_ThrowsArgumentException_WhenSeedLengthIsInvalid()
		{
			AssertLite.Throws<ArgumentException>(() =>
			{
				Span<byte> seed = stackalloc byte[RandomGenerator.SeedLen - 1];
				Span<byte> buffer = stackalloc byte[32];
				RandomGenerator.FillDeterministic(buffer, seed);
			});
		}

#if !LINUX

		[Test]
		[NotInParallel]
		public void CloseAndStir_WorksAsExpected()
		{
			try
			{
				RandomGenerator.Stir();
				RandomGenerator.Stir();
				RandomGenerator.Close();
				AssertLite.Throws<LibSodiumException>(() => RandomGenerator.Close());
			}
			finally
			{
				RandomGenerator.Stir();
			}
		}
#endif
	}
}
