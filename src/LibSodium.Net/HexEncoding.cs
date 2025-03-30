using LibSodium.Interop;
using System.Text;

namespace LibSodium
{
	/// <summary>
	/// Provides methods for encoding and decoding hexadecimal strings and byte buffers.
	/// </summary>
	public static class HexEncoding
	{
		/// <summary>
		/// Converts a byte buffer to a hexadecimal string in constant time for a given size.
		/// </summary>
		/// <param name="bin">The byte buffer to convert.</param>
		/// <returns>A hexadecimal string representation of the byte buffer.</returns>
		public static string BinToHex(ReadOnlySpan<byte> bin)
		{
			LibraryInitializer.EnsureInitialized();
			if (bin.Length == 0)
			{
				return string.Empty;
			}
			int hexAsciiBytesLen = bin.Length * 2 + 1;
			Span<byte> hexAsciiBytes = hexAsciiBytesLen <= Constants.MaxStackAlloc ? stackalloc byte[hexAsciiBytesLen] : new byte[hexAsciiBytesLen];
			var result = Native.sodium_bin2hex(hexAsciiBytes, (nuint)hexAsciiBytesLen, bin, (nuint)bin.Length);
			if (result == 0)
			{
				throw new LibSodiumException("sodium_bin2hex failed");
			}
			return Encoding.ASCII.GetString(hexAsciiBytes.Slice(0, hexAsciiBytes.Length - 1));
		}

		/// <summary>
		/// Converts a byte buffer to a hexadecimal string using a provided character span.
		/// </summary>
		/// <param name="bin">The byte buffer to convert.</param>
		/// <param name="hex">The span to write the hexadecimal string into.</param>
		/// <returns>A span containing the hexadecimal string representation.</returns>
		public static Span<char> BinToHex(ReadOnlySpan<byte> bin, Span<char> hex)
		{
			LibraryInitializer.EnsureInitialized();
			if (hex.Length < bin.Length * 2)
			{
				throw new ArgumentException("hex buffer must be at least twice the size of the bin buffer");
			}
			if (bin.Length == 0)
			{
				return hex.Slice(0, 0);
			}
			int hexAsciiBytesLen = bin.Length * 2 + 1;
			Span<byte> hexAsciiBytes = hexAsciiBytesLen <= Constants.MaxStackAlloc ? stackalloc byte[hexAsciiBytesLen] : new byte[hexAsciiBytesLen];
			var result = Native.sodium_bin2hex(hexAsciiBytes, (nuint)hexAsciiBytesLen, bin, (nuint)bin.Length);
			if (result == 0)
			{
				throw new LibSodiumException("sodium_bin2hex failed");
			}
			Encoding.ASCII.GetChars(hexAsciiBytes.Slice(0, hexAsciiBytesLen - 1), hex);
			return hex.Slice(0, hexAsciiBytesLen - 1);
		}

		/// <summary>
		/// Converts a hexadecimal string to a byte buffer.
		/// </summary>
		/// <param name="hex">The hexadecimal string to convert.</param>
		/// <param name="bin">The span to write the byte buffer into.</param>
		/// <param name="ignore">Optional characters to ignore during conversion.</param>
		/// <returns>A span containing the converted byte buffer.</returns>
		public static Span<byte> HexToBin(string hex, Span<byte> bin, string? ignore = null)
		{
			return HexToBin(hex.AsSpan(), bin, ignore);
		}

		/// <summary>
		/// Converts a span of characters representing a hexadecimal string to a byte buffer.
		/// </summary>
		/// <param name="hex">The span of characters representing the hexadecimal string.</param>
		/// <param name="bin">The span to write the byte buffer into.</param>
		/// <param name="ignore">Optional characters to ignore during conversion.</param>
		/// <returns>A span containing the converted byte buffer.</returns>
		public static Span<byte> HexToBin(ReadOnlySpan<char> hex, Span<byte> bin, string? ignore = null)
		{
			LibraryInitializer.EnsureInitialized();
			if (hex.Length == 0)
			{
				return bin.Slice(0, 0);
			}
			ignore ??= string.Empty;
			Span<byte> ignoreBytes = stackalloc byte[ignore.Length + 1];
			Encoding.ASCII.GetBytes(ignore.AsSpan(), ignoreBytes);
			Span<byte> hexBytes = hex.Length <= Constants.MaxStackAlloc ? stackalloc byte[hex.Length] : new byte[hex.Length];
			Encoding.ASCII.GetBytes(hex, hexBytes);

			if (Native.sodium_hex2bin(bin, (nuint)bin.Length, hexBytes, (nuint)hex.Length, ignoreBytes, out nuint bin_len, nint.Zero) != 0)
			{
				throw new LibSodiumException("sodium_hex2bin failed because hex string contains invalid characters or the destination bin buffer is too short");
			}
			return bin.Slice(0, (int)bin_len);
		}
	}
}
