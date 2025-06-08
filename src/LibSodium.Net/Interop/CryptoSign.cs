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

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_ed25519_pk_to_curve25519))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]

		internal static partial int crypto_sign_ed25519_pk_to_curve25519(
			Span<byte> curve25519PublicKey,
			ReadOnlySpan<byte> ed25519PublicKey);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_ed25519_sk_to_curve25519))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign_ed25519_sk_to_curve25519(
			Span<byte> curve25519SecretKey,
			ReadOnlySpan<byte> ed25519SecretKey);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nuint crypto_sign_statebytes();


		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign_init(Span<byte> state);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign_update(Span<byte> state, ReadOnlySpan<byte> message, nuint messageLength);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_final_create))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign_final_create(
			Span<byte> state,
			Span<byte> signature,
			out ulong signatureLength,
			ReadOnlySpan<byte> privateKey);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_sign_final_verify))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_sign_final_verify(
			Span<byte> state, 
			ReadOnlySpan<byte> signature,
			ReadOnlySpan<byte> publicKey);

	}
}
