using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		internal const int CRYPTO_SIGN_PUBLICKEYBYTES = 32;
		internal const int CRYPTO_SIGN_SECRETKEYBYTES = 64;
		internal const int CRYPTO_SIGN_BYTES = 64;
		internal const int CRYPTO_SIGN_SEEDBYTES = 32;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_keypair))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign_keypair(
			Span<byte> public_key,
			Span<byte> private_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_seed_keypair))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign_seed_keypair(
			Span<byte> public_key,
			Span<byte> private_key,
			ReadOnlySpan<byte> seed);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign(
			Span<byte> signed_message,
			out ulong signed_message_len,
			ReadOnlySpan<byte> message,
			ulong message_len,
			ReadOnlySpan<byte> private_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_open))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign_open(
			Span<byte> message,
			out ulong message_len,
			ReadOnlySpan<byte> signed_message,
			ulong signed_message_len,
			ReadOnlySpan<byte> public_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_detached))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign_detached(
			Span<byte> signature,
			out ulong signature_len,
			ReadOnlySpan<byte> message,
			ulong message_len,
			ReadOnlySpan<byte> private_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_verify_detached))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign_verify_detached(
			ReadOnlySpan<byte> signature,
			ReadOnlySpan<byte> message,
			ulong message_len,
			ReadOnlySpan<byte> pk);
	}
}
