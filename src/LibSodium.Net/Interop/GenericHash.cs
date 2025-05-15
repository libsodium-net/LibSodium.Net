using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		internal const int CRYPTO_GENERICHASH_BYTES = 32;
		internal const int CRYPTO_GENERICHASH_BYTES_MIN = 16;
		internal const int CRYPTO_GENERICHASH_BYTES_MAX = 64;
		internal const int CRYPTO_GENERICHASH_KEYBYTES = 32;
		internal const int CRYPTO_GENERICHASH_KEYBYTES_MIN = 16;
		internal const int CRYPTO_GENERICHASH_KEYBYTES_MAX = 64;


		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_generichash))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_generichash(
			Span<byte> output, nuint outputLength,
			ReadOnlySpan<byte> input, ulong inputLength,
			ReadOnlySpan<byte> key, nuint keyLength);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_generichash_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nuint crypto_generichash_statebytes();

		// write libraryimport for int crypto_generichash_init
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_generichash_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_generichash_init(
			Span<byte> state,
			ReadOnlySpan<byte> key, 
			nuint key_len,
			nuint hash_len);

		// write libraryimport for int crypto_generichash_update
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_generichash_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_generichash_update(
			Span<byte> state,
			ReadOnlySpan<byte> input,
			ulong input_len);

		// write libraryimport for int crypto_generichash_final
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_generichash_final))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_generichash_final(
			Span<byte> state,
			Span<byte> hash,
			nuint hash_len);

	}
}
