using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		public const int CRYPTO_HASH_SHA256_BYTES = 32;
		public const int CRYPTO_HASH_SHA512_BYTES = 64;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha256))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha256(Span<byte> hash, ReadOnlySpan<byte> input, ulong input_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha512))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha512(Span<byte> hash, ReadOnlySpan<byte> input, ulong input_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha256_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nuint crypto_hash_sha256_statebytes();

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha256_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha256_init(Span<byte> state);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha256_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha256_update(Span<byte> state, ReadOnlySpan<byte> input, ulong input_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha256_final))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha256_final(Span<byte> state, Span<byte> hash);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha512_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nuint crypto_hash_sha512_statebytes();

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha512_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha512_init(Span<byte> state);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha512_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha512_update(Span<byte> state, ReadOnlySpan<byte> input, ulong input_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha512_final))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha512_final(Span<byte> state, Span<byte> hash);
	}
}