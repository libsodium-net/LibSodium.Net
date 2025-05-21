// This file defines the native interop bindings for all four stream ciphers:
// - XSalsa20
// - Salsa20
// - ChaCha20
// - XChaCha20

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop;

internal static partial class Native
{
	// ===== XSalsa20 =====
	internal const int CRYPTO_STREAM_XSALSA20_KEYBYTES = 32;
	internal const int CRYPTO_STREAM_XSALSA20_NONCEBYTES = 24;
	public const string CRYPTO_STREAM_XSALSA20_PRIMITIVE = "xsalsa20";

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_xsalsa20")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_xsalsa20(
		Span<byte> c,
		ulong clen,
		ReadOnlySpan<byte> n,
		ReadOnlySpan<byte> k);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_xsalsa20_xor")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_xsalsa20_xor(
		Span<byte> c,
		ReadOnlySpan<byte> m,
		ulong mlen,
		ReadOnlySpan<byte> n,
		ReadOnlySpan<byte> k);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_xsalsa20_xor_ic")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_xsalsa20_xor_ic(
		Span<byte> c,
		ReadOnlySpan<byte> m,
		ulong mlen,
		ReadOnlySpan<byte> n,
		ulong ic,
		ReadOnlySpan<byte> k);

	// ===== Salsa20 =====
	internal const int CRYPTO_STREAM_SALSA20_KEYBYTES = 32;
	internal const int CRYPTO_STREAM_SALSA20_NONCEBYTES = 8;
	public const string CRYPTO_STREAM_SALSA20_PRIMITIVE = "salsa20";

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_salsa20")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_salsa20(
		Span<byte> c,
		ulong clen,
		ReadOnlySpan<byte> n,
		ReadOnlySpan<byte> k);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_salsa20_xor")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_salsa20_xor(
		Span<byte> c,
		ReadOnlySpan<byte> m,
		ulong mlen,
		ReadOnlySpan<byte> n,
		ReadOnlySpan<byte> k);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_salsa20_xor_ic")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_salsa20_xor_ic(
		Span<byte> c,
		ReadOnlySpan<byte> m,
		ulong mlen,
		ReadOnlySpan<byte> n,
		ulong ic,
		ReadOnlySpan<byte> k);

	// ===== ChaCha20 =====
	internal const int CRYPTO_STREAM_CHACHA20_KEYBYTES = 32;
	internal const int CRYPTO_STREAM_CHACHA20_NONCEBYTES = 8;
	public const string CRYPTO_STREAM_CHACHA20_PRIMITIVE = "chacha20";

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_chacha20")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_chacha20(
		Span<byte> c,
		ulong clen,
		ReadOnlySpan<byte> n,
		ReadOnlySpan<byte> k);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_chacha20_xor")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_chacha20_xor(
		Span<byte> c,
		ReadOnlySpan<byte> m,
		ulong mlen,
		ReadOnlySpan<byte> n,
		ReadOnlySpan<byte> k);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_chacha20_xor_ic")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_chacha20_xor_ic(
		Span<byte> c,
		ReadOnlySpan<byte> m,
		ulong mlen,
		ReadOnlySpan<byte> n,
		ulong ic,
		ReadOnlySpan<byte> k);

	// ===== XChaCha20 =====
	internal const int CRYPTO_STREAM_XChaCha20_KEYBYTES = 32;
	internal const int CRYPTO_STREAM_XChaCha20_NONCEBYTES = 24;
	public const string CRYPTO_STREAM_XChaCha20_PRIMITIVE = "xchacha20";

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_xchacha20")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_xchacha20(
		Span<byte> c,
		ulong clen,
		ReadOnlySpan<byte> n,
		ReadOnlySpan<byte> k);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_xchacha20_xor")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_xchacha20_xor(
		Span<byte> c,
		ReadOnlySpan<byte> m,
		ulong mlen,
		ReadOnlySpan<byte> n,
		ReadOnlySpan<byte> k);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_xchacha20_xor_ic")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_xchacha20_xor_ic(
		Span<byte> c,
		ReadOnlySpan<byte> m,
		ulong mlen,
		ReadOnlySpan<byte> n,
		ulong ic,
		ReadOnlySpan<byte> k);

	// ===== ChaCha20-IETF =====
	internal const int CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES = 32;
	internal const int CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES = 12;
	public const string CRYPTO_STREAM_CHACHA20_IETF_PRIMITIVE = "chacha20-ietf";

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_chacha20_ietf")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_chacha20_ietf(
		Span<byte> c,
		ulong clen,
		ReadOnlySpan<byte> n,
		ReadOnlySpan<byte> k);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_chacha20_ietf_xor")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_chacha20_ietf_xor(
		Span<byte> c,
		ReadOnlySpan<byte> m,
		ulong mlen,
		ReadOnlySpan<byte> n,
		ReadOnlySpan<byte> k);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = "crypto_stream_chacha20_ietf_xor_ic")]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_stream_chacha20_ietf_xor_ic(
		Span<byte> c,
		ReadOnlySpan<byte> m,
		ulong mlen,
		ReadOnlySpan<byte> n,
		uint ic, // IETF version uses uint instead of ulong
		ReadOnlySpan<byte> k);
}
