using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		internal const int CRYPTO_AUTH_KEYBYTES = 32;
		internal const int CRYPTO_AUTH_BYTES = 32;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_auth(
			Span<byte> output, 
			ReadOnlySpan<byte> input,
            ulong input_len, 
			ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_verify))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_auth_verify(
			ReadOnlySpan<byte> mac, 
			ReadOnlySpan<byte> input,
            ulong input_len,
			ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_auth_keygen))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial void crypto_auth_keygen(Span<byte> key);
	}
}
