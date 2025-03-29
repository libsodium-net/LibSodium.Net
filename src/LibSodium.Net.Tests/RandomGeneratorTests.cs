using TUnit.Assertions.AssertConditions.Throws;

namespace LibSodium.Tests
{
	public class RandomGeneratorTests
	{
		[Test]
		public async Task GetUInt32_ReturnsRandomUInt32()
		{
			uint random1 = RandomGenerator.GetUInt32();
			uint random2 = RandomGenerator.GetUInt32();
			
			await Assert.That(random1).IsNotEqualTo(random2);
			
		}

		[Test]
		public async Task GetUInt32_WithUpperBound_ReturnsRandomUInt32LessThanUpperBound()
		{
			uint upperBound = 100;
			uint random = RandomGenerator.GetUInt32(upperBound);

			await Assert.That(random).IsLessThan(upperBound);
		}

		[Test]
		public async Task Fill_FillsBufferWithRandomBytes()
		{
			var b1 = new byte[32];
			var b2 = new byte[32];
			var zeroes = new byte[32];

			RandomGenerator.Fill(b1);
			RandomGenerator.Fill(b2);


			await Assert.That(b1).IsNotSequenceEqualTo(b2);
			await Assert.That(b1).IsNotSequenceEqualTo(zeroes);
			await Assert.That(b2).IsNotSequenceEqualTo(zeroes);

		}

		[Test]
		public async Task FillDeterministic_FillsBufferWithDeterministicRandomBytes()
		{
			Span<byte> s1 = stackalloc byte[RandomGenerator.SeedLen];
			Span<byte> s2 = stackalloc byte[RandomGenerator.SeedLen];

			Random random = new Random();
			random.NextBytes(s1);
			random.NextBytes(s2);

			var b1s1 = new byte[32];
			var b2s1 = new byte[32];
			var b3s2 = new byte[32];

			RandomGenerator.FillDeterministic(b1s1, s1);
			RandomGenerator.FillDeterministic(b2s1, s1);
			RandomGenerator.FillDeterministic(b3s2, s2);

			await Assert.That(b1s1).IsSequenceEqualTo(b2s1);
			await Assert.That(b1s1).IsNotSequenceEqualTo(b3s2);

		}

		[Test]
		public async Task FillDeterministic_ThrowsArgumentException_WhenSeedLengthIsInvalid()
		{
			byte[] seed = new byte[RandomGenerator.SeedLen - 1];
			byte[] buffer = new byte[32];

			await Assert.That(() => RandomGenerator.FillDeterministic(buffer, seed)).Throws<ArgumentException>();
		}

		[Test]
		[NotInParallel]
		public async Task CloseAndStir_WorksAsExpected()
		{
			try
			{
				await Assert.That(() => RandomGenerator.Stir()).ThrowsNothing();
				await Assert.That(() => RandomGenerator.Stir()).ThrowsNothing();
				await Assert.That(() => RandomGenerator.Close()).ThrowsNothing();
				await Assert.That(() => RandomGenerator.Close()).Throws<SodioException>();
			}
			finally
			{
				RandomGenerator.Stir();
			}
		}
	}
}
