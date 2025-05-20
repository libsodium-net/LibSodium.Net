using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop;

internal static partial class Native
{
	// 📏 Constants for HMAC-SHA-2
	internal const int CRYPTO_AUTH_HMACSHA256_BYTES = 32;
	internal const int CRYPTO_AUTH_HMACSHA256_KEYBYTES = 32;

	internal const int CRYPTO_AUTH_HMACSHA512_BYTES = 64;
	internal const int CRYPTO_AUTH_HMACSHA512_KEYBYTES = 32;

	internal const int CRYPTO_AUTH_HMACSHA512256_BYTES = 32;
	internal const int CRYPTO_AUTH_HMACSHA512256_KEYBYTES = 32;

	// HMAC-SHA-256
	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha256))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha256(
		Span<byte> mac,
		ReadOnlySpan<byte> message,
		ulong messageLength,
		ReadOnlySpan<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha256_verify))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha256_verify(
		ReadOnlySpan<byte> mac,
		ReadOnlySpan<byte> message,
		ulong messageLength,
		ReadOnlySpan<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha256_init))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha256_init(
		Span<byte> state,
		ReadOnlySpan<byte> key,
		nuint keyLength);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha256_update))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha256_update(
		Span<byte> state,
		ReadOnlySpan<byte> message,
		ulong messageLength);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha256_final))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha256_final(
		Span<byte> state,
		Span<byte> mac);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha256_keygen))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial void crypto_auth_hmacsha256_keygen(
		Span<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha256_statebytes))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial nuint crypto_auth_hmacsha256_statebytes();


	// HMAC-SHA-512
	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha512(
		Span<byte> mac,
		ReadOnlySpan<byte> message,
		ulong messageLength,
		ReadOnlySpan<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512_verify))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha512_verify(
		ReadOnlySpan<byte> mac,
		ReadOnlySpan<byte> message,
		ulong messageLength,
		ReadOnlySpan<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512_init))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha512_init(
		Span<byte> state,
		ReadOnlySpan<byte> key,
		nuint keyLength);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512_update))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha512_update(
		Span<byte> state,
		ReadOnlySpan<byte> message,
		ulong messageLength);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512_final))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha512_final(
		Span<byte> state,
		Span<byte> mac);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512_keygen))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial void crypto_auth_hmacsha512_keygen(
		Span<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512_statebytes))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial nuint crypto_auth_hmacsha512_statebytes();


	// HMAC-SHA-512-256
	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512256))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha512256(
		Span<byte> mac,
		ReadOnlySpan<byte> message,
		ulong messageLength,
		ReadOnlySpan<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512256_verify))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha512256_verify(
		ReadOnlySpan<byte> mac,
		ReadOnlySpan<byte> message,
		ulong messageLength,
		ReadOnlySpan<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512256_init))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha512256_init(
		Span<byte> state,
		ReadOnlySpan<byte> key,
		nuint keyLength);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512256_update))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha512256_update(
		Span<byte> state,
		ReadOnlySpan<byte> message,
		ulong messageLength);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512256_final))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_auth_hmacsha512256_final(
		Span<byte> state,
		Span<byte> mac);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512256_keygen))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial void crypto_auth_hmacsha512256_keygen(
		Span<byte> key);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_hmacsha512256_statebytes))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial nuint crypto_auth_hmacsha512256_statebytes();
}
