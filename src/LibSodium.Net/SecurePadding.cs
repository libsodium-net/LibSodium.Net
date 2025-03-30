using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides methods for padding and unpadding byte buffers to ensure they meet specified block sizes.
	/// </summary>
	public static class SecurePadding
	{
		/// <summary>
		/// Pads the given buffer to the specified block size.
		/// </summary>
		/// <param name="buffer">The buffer to pad.</param>
		/// <param name="unpaddedLen">The length of the data before padding.</param>
		/// <param name="blockSize">The block size to pad to.</param>
		/// <returns>A span of the padded buffer.</returns>
		/// <exception cref="ArgumentException">Thrown when blockSize is less than or equal to 0 or unpaddedLen is greater than buffer length.</exception>
		public static Span<byte> Pad(Span<byte> buffer, int unpaddedLen, int blockSize)
		{
			LibraryInitializer.EnsureInitialized();
			if (blockSize <= 0)
			{
				throw new ArgumentException("block_size must be greater than 0");
			}
			if (unpaddedLen > buffer.Length)
			{
				throw new ArgumentException("unpadded_len must be less than or equal to buffer.Length");
			}
			if (Native.sodium_pad(out nuint padded_len, buffer, (nuint)unpaddedLen, (nuint)blockSize, (nuint)buffer.Length) != 0)
			{
				throw new ArgumentException("Padding failed because the buffer is too short");
			}
			return buffer.Slice(0, (int)padded_len);
		}

		/// <summary>
		/// Unpads the given buffer that was padded to a specified block size.
		/// </summary>
		/// <param name="buffer">The buffer to unpad.</param>
		/// <param name="blockSize">The block size that was used for padding.</param>
		/// <returns>A span of the unpadded buffer.</returns>
		/// <exception cref="ArgumentException">Thrown when blockSize is less than or equal to 0.</exception>
		/// <exception cref="LibSodiumException">Thrown when unpadding fails.</exception>
		public static Span<byte> Unpad(Span<byte> buffer, int blockSize)
		{
			LibraryInitializer.EnsureInitialized();
			if (blockSize <= 0)
			{
				throw new ArgumentException("block_size must be greater than 0");
			}
			if (Native.sodium_unpad(out nint unpadded_len, buffer, (nuint)buffer.Length, (nuint)blockSize) != 0)
			{
				throw new LibSodiumException("Unpadding failed");
			}
			return buffer.Slice(0, (int)unpadded_len);
		}
	}
}
