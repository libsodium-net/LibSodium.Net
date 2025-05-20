using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop;

internal static partial class Native
{
	public const int CRYPTO_ONETIMEAUTH_BYTES = 16;
	public const int CRYPTO_ONETIMEAUTH_KEYBYTES = 32;
	public const string CRYPTO_ONETIMEAUTH_PRIMITIVE = "poly1305";

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_onetimeauth))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_onetimeauth(
		Span<byte> mac,
		ReadOnlySpan<byte> message,
		ulong messageLen,
		ReadOnlySpan<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_onetimeauth_verify))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_onetimeauth_verify(
		ReadOnlySpan<byte> mac,
		ReadOnlySpan<byte> message,
		ulong messageLen,
		ReadOnlySpan<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_onetimeauth_statebytes))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial nuint crypto_onetimeauth_statebytes();

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_onetimeauth_init))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_onetimeauth_init(
		Span<byte> state,
		ReadOnlySpan<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_onetimeauth_update))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_onetimeauth_update(
		Span<byte> state,
		ReadOnlySpan<byte> message,
		ulong messageLen);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_onetimeauth_final))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_onetimeauth_final(
		Span<byte> state,
		Span<byte> mac);
}
