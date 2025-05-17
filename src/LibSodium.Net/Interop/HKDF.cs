using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		public const int CRYPTO_KDF_HKDF_SHA256_KEYBYTES = 32;
		public const int CRYPTO_KDF_HKDF_SHA256_BYTES_MIN = 0;
		public const int CRYPTO_KDF_HKDF_SHA256_BYTES_MAX = 8160;

		public const int CRYPTO_KDF_HKDF_SHA512_KEYBYTES = 64;
		public const int CRYPTO_KDF_HKDF_SHA512_BYTES_MIN = 0;
		public const int CRYPTO_KDF_HKDF_SHA512_BYTES_MAX = 16320;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_extract))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha256_extract(
			Span<byte> prk,
			ReadOnlySpan<byte> salt,
			nuint salt_len,
			ReadOnlySpan<byte> ikm,
			nuint ikm_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_expand))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha256_expand(
			Span<byte> okm,
			nuint okm_len,
			ReadOnlySpan<byte> info,
			nuint info_len,
			ReadOnlySpan<byte> prk);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_extract))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha512_extract(
			Span<byte> prk,
			ReadOnlySpan<byte> salt,
			nuint saltLen,
			ReadOnlySpan<byte> ikm,
			nuint ikmLen);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_expand))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha512_expand(
			Span<byte> okm,
			nuint okmLen,
			ReadOnlySpan<byte> info,
			nuint infoLen,
			ReadOnlySpan<byte> prk);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial nuint crypto_kdf_hkdf_sha256_statebytes();

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial nuint crypto_kdf_hkdf_sha512_statebytes();

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_extract_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha256_extract_init(
			Span<byte> state,
			ReadOnlySpan<byte> salt,
			nuint salt_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_extract_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha256_extract_update(
			Span<byte> state,
			ReadOnlySpan<byte> ikm,
			nuint ikm_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_extract_final))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha256_extract_final(
			Span<byte> state,
			Span<byte> prk);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_extract_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha512_extract_init(
			Span<byte> state,
			ReadOnlySpan<byte> salt,
			nuint salt_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_extract_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha512_extract_update(
			Span<byte> state,
			ReadOnlySpan<byte> ikm,
			nuint ikm_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_extract_final))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha512_extract_final(
			Span<byte> state,
			Span<byte> prk);
	}
}
