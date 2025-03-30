using LibSodium.Interop;
using System.Text;

namespace LibSodium
{
	/// <summary>Represents Base64 encoding variants.</summary>
	public enum Base64Variant
	{
		/// <summary>Original Base64 encoding variant.</summary>
		Original = Native.sodium_base64_VARIANT_ORIGINAL,
		/// <summary>Original Base64 encoding variant with no padding.</summary>
		OriginalNoPadding = Native.sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
		/// <summary>URL safe Base64 encoding variant.</summary>
		UrlSafe = Native.sodium_base64_VARIANT_URLSAFE,
		/// <summary>URL safe Base64 encoding variant with no padding.</summary>
		UrlSafeNoPadding = Native.sodium_base64_VARIANT_URLSAFE_NO_PADDING,
	}


	/// <summary>Provides methods for Base64 encoding and decoding.</summary>
	public static class Base64Encoding
	{
		/// <summary>Calculates the maximum length of the decoded binary data from a Base64 string.</summary>
		/// <param name="base64Len">The length of the Base64 string.</param>
		/// <returns>The maximum length of the decoded binary data.</returns>
		public static int GetBase64DecodedMaxLen(int base64Len)
		{
			return base64Len * 3 / 4;
		}

		/// <summary>Calculates the length of the Base64 encoded string for a given binary length.</summary>
		/// <param name="binLen">The length of the binary data.</param>
		/// <param name="variant">The Base64 variant to use.</param>
		/// <param name="includeNullTerminator">Indicates whether to include a null terminator in the length calculation.</param>
		/// <returns>The length of the Base64 encoded string.</returns>
		public static int GetBase64EncodedLen(int binLen, Base64Variant variant, bool includeNullTerminator = true)
		{
			LibraryInitializer.EnsureInitialized();
			var len = (int)Native.sodium_base64_encoded_len((nuint)binLen, (int)variant);
			return includeNullTerminator ? len : len - 1;
		}

		/// <summary>Decodes a Base64 string into a binary representation.</summary>
		/// <param name="b64">The Base64 string to decode.</param>
		/// <param name="bin">The span to store the decoded binary data.</param>
		/// <param name="variant">The Base64 variant to use.</param>
		/// <param name="ignore">Characters to ignore during decoding.</param>
		/// <returns>A span containing the decoded binary data.</returns>
		public static Span<byte> Base64ToBin(string b64, Span<byte> bin, Base64Variant variant, string? ignore = null)
		{
			return Base64ToBin(b64.AsSpan(), bin, variant, ignore);
		}

		/// <summary>Decodes a Base64 string into a binary representation.</summary>
		/// <param name="b64">The Base64 string to decode as a ReadOnlySpan.</param>
		/// <param name="bin">The span to store the decoded binary data.</param>
		/// <param name="variant">The Base64 variant to use.</param>
		/// <param name="ignore">Characters to ignore during decoding.</param>
		/// <returns>A span containing the decoded binary data.</returns>
		public static Span<byte> Base64ToBin(ReadOnlySpan<char> b64, Span<byte> bin, Base64Variant variant, string? ignore = null)
		{
			LibraryInitializer.EnsureInitialized();
			if (b64.Length == 0)
			{
				return bin.Slice(0, 0);
			}
			ignore ??= string.Empty;
			Span<byte> ignoreBytes = stackalloc byte[ignore.Length + 1];
			Encoding.ASCII.GetBytes(ignore.AsSpan(), ignoreBytes);
			Span<byte> b64AsciiBytes = b64.Length <= Constants.MaxStackAlloc ? stackalloc byte[b64.Length] : new byte[b64.Length];
			Encoding.ASCII.GetBytes(b64, b64AsciiBytes);
			if (Native.sodium_base642bin(bin, (nuint)bin.Length, b64AsciiBytes, (nuint)b64.Length, ignoreBytes, out nuint bin_len, nint.Zero, (int)variant) != 0)
			{
				throw new LibSodiumException("sodium_base642bin failed because Base64 contains invalid characters or the destination bin buffer is too short");
			}
			return bin.Slice(0, (int)bin_len);
		}

		/// <summary>Encodes binary data into a Base64 string.</summary>
		/// <param name="bin">The binary data to encode.</param>
		/// <param name="variant">The Base64 variant to use.</param>
		/// <returns>A Base64 encoded string.</returns>
		public static string BinToBase64(ReadOnlySpan<byte> bin, Base64Variant variant)
		{
			LibraryInitializer.EnsureInitialized();
			if (bin.Length == 0)
			{
				return string.Empty;
			}
			int b64AsciiBytesLen = GetBase64EncodedLen(bin.Length, variant);
			Span<byte> b64AsciiBytes = b64AsciiBytesLen <= Constants.MaxStackAlloc ? stackalloc byte[b64AsciiBytesLen] : new byte[b64AsciiBytesLen];
			var result = Native.sodium_bin2base64(b64AsciiBytes, (nuint)b64AsciiBytes.Length, bin, (nuint)bin.Length, (int)variant);
			if (result == 0)
			{
				throw new LibSodiumException("sodium_bin2base64 failed");
			}
			return Encoding.ASCII.GetString(b64AsciiBytes.Slice(0, b64AsciiBytesLen - 1));
		}

		/// <summary>Encodes binary data into a Base64 representation and stores it in a character span.</summary>
		/// <param name="bin">The binary data to encode.</param>
		/// <param name="b64">The span to store the Base64 encoded data.</param>
		/// <param name="variant">The Base64 variant to use.</param>
		/// <returns>A span containing the Base64 encoded data.</returns>
		public static Span<char> BinToBase64(ReadOnlySpan<byte> bin, Span<char> b64, Base64Variant variant)
		{
			LibraryInitializer.EnsureInitialized();
			if (bin.Length == 0)
			{
				return b64.Slice(0, 0);
			}
			int b64AsciiBytesLen = GetBase64EncodedLen(bin.Length, variant);
			if (b64.Length < b64AsciiBytesLen - 1)
			{
				throw new ArgumentException("b64 buffer is too short", nameof(b64));
			}
			Span<byte> b64AsciiBytes = b64AsciiBytesLen <= Constants.MaxStackAlloc ? stackalloc byte[b64AsciiBytesLen] : new byte[b64AsciiBytesLen];
			var result = Native.sodium_bin2base64(b64AsciiBytes, (nuint)b64AsciiBytes.Length, bin, (nuint)bin.Length, (int)variant);
			if (result == 0)
			{
				throw new LibSodiumException("sodium_bin2base64 failed");
			}
			Encoding.ASCII.GetChars(b64AsciiBytes.Slice(0, b64AsciiBytesLen - 1), b64);
			return b64.Slice(0, b64AsciiBytesLen - 1);
		}
	}
}
