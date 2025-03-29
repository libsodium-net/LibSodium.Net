using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		internal const int sodium_base64_VARIANT_ORIGINAL = 1;
		internal const int sodium_base64_VARIANT_ORIGINAL_NO_PADDING = 3;
		internal const int sodium_base64_VARIANT_URLSAFE = 5;
		internal const int sodium_base64_VARIANT_URLSAFE_NO_PADDING = 7;

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_memcmp(ReadOnlySpan<byte> b1, ReadOnlySpan<byte> b2, nuint len);

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nint sodium_bin2hex(Span<byte> hex, nuint hex_maxlen, ReadOnlySpan<byte> bin, nuint bin_len);

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_hex2bin(Span<byte> bin, nuint bin_maxlen, Span<byte> hex, nuint hex_len, Span<byte> ignore, out nuint bin_len, nint hex_end);

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_base642bin(
			Span<byte> bin, nuint bin_maxlen,
			ReadOnlySpan<byte> b64, nuint b64_len,
			Span<byte> ignore, out nuint bin_len,
			nint b64_end, int variant);

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nuint sodium_base64_encoded_len(nuint bin_len, int variant);

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nint sodium_bin2base64(
			Span<byte> b64, nuint b64_maxlen,
			ReadOnlySpan<byte> bin, nuint bin_len,
			int variant);

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial void sodium_increment(Span<byte> number, nuint len);

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial void sodium_add(Span<byte> a, ReadOnlySpan<byte> b, nuint len);

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial void sodium_sub(Span<byte> a, ReadOnlySpan<byte> b, nuint len);

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial	int sodium_compare(ReadOnlySpan<byte> b1, ReadOnlySpan<byte> b2, nuint len);

		[LibraryImport("libsodium")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_is_zero(ReadOnlySpan<byte> n, nuint len);
	}
}
