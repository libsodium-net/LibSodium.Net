using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Static class for random number generation.
	/// </summary>
	public static class RandomGenerator
	{
		/// <summary>
		/// The length of the seed used for deterministic random byte generation.
		/// </summary>
		public const int SeedLen = Native.RANDOMBYTES_SEEDBYTES;

		/// <summary>
		/// Gets a random unsigned 32-bit integer.
		/// </summary>
		/// <returns>A random unsigned 32-bit integer.</returns>
		public static uint GetUInt32()
		{
			LibraryInitializer.EnsureInitialized();
			return Native.randombytes_random();
		}

		/// <summary>
		/// Gets a random unsigned 32-bit integer less than the specified upper bound.
		/// </summary>
		/// <param name="upperBound">The upper bound (exclusive) for the random number.</param>
		/// <returns>A random unsigned 32-bit integer less than upperBound.</returns>
		public static uint GetUInt32(uint upperBound)
		{
			LibraryInitializer.EnsureInitialized();
			return Native.randombytes_uniform(upperBound);
		}

		/// <summary>
		/// Fills the specified buffer with random bytes.
		/// </summary>
		/// <param name="buffer">The buffer to fill with random bytes.</param>
		public static void Fill(Span<byte> buffer)
		{
			LibraryInitializer.EnsureInitialized();
			Native.randombytes_buf(buffer, (nuint)buffer.Length);
		}

		/// <summary>
		/// Fills the specified secure memory buffer with random bytes.
		/// </summary>
		/// <param name="buffer">The buffer to fill with random bytes.</param>
		public static void Fill(SecureMemory<byte> buffer)
		{
			Fill(buffer.AsSpan());
		}

		/// <summary>
		/// Fills the specified buffer with deterministic random bytes based on the provided seed.
		/// It produces the same sequence of random bytes for the same seed.
		/// </summary>
		/// <param name="buffer">The buffer to fill with deterministic random bytes.</param>
		/// <param name="seed">The seed used for deterministic random byte generation.</param>
		/// <exception cref="ArgumentException">Thrown when the seed length is not equal to SeedLen.</exception>
		public static void FillDeterministic(Span<byte> buffer, ReadOnlySpan<byte> seed)
		{
			LibraryInitializer.EnsureInitialized();
			if (seed.Length != SeedLen)
			{
				throw new ArgumentException($"seed must be {SeedLen} bytes in length", nameof(seed));
			}
			Native.randombytes_buf_deterministic(buffer, (nuint)buffer.Length, seed);
		}

		/// <summary>
		/// Fills the specified buffer with deterministic random bytes based on the provided seed.
		/// It produces the same sequence of random bytes for the same seed.
		/// </summary>
		/// <param name="buffer">The buffer to fill with deterministic random bytes.</param>
		/// <param name="seed">The seed used for deterministic random byte generation.</param>
		/// <exception cref="ArgumentException">Thrown when the seed length is not equal to SeedLen.</exception>
		public static void FillDeterministic(SecureMemory<byte> buffer, SecureMemory<byte> seed)
		{
			FillDeterministic(buffer.AsSpan(), seed.AsReadOnlySpan());
		}

		/// <summary>
		/// Closes the random number generator.
		/// </summary>
		/// <exception cref="LibSodiumException">Thrown when randombytes_close() fails.</exception>
		public static void Close()
		{
			LibraryInitializer.EnsureInitialized();
			if (Native.randombytes_close() != 0)
			{
				throw new LibSodiumException("randombytes_close() failed");
			}
		}

		/// <summary>
		/// Stirs the random number generator to ensure randomness.
		/// </summary>
		public static void Stir()
		{
			LibraryInitializer.EnsureInitialized();
			Native.randombytes_stir();
		}
	}
}
