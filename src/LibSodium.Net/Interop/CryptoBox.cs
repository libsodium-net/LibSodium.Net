using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		internal const int CRYPTO_BOX_PUBLICKEYBYTES = 32;
		internal const int CRYPTO_BOX_SECRETKEYBYTES = 32;
		internal const int CRYPTO_BOX_BEFORENMBYTES = 32;
		internal const int CRYPTO_BOX_NONCEBYTES = 24;
		internal const int CRYPTO_BOX_MACBYTES = 16;
		internal const int CRYPTO_BOX_SEEDBYTES = 32;
		internal const int CRYPTO_BOX_SEALBYTES = CRYPTO_BOX_PUBLICKEYBYTES + CRYPTO_BOX_MACBYTES;


		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_keypair))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_keypair(
			Span<byte> public_key, 
			Span<byte> private_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_seed_keypair))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_seed_keypair(
			Span<byte> public_key,
			Span<byte> private_key,
			ReadOnlySpan<byte> seed);


		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_scalarmult_base))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_scalarmult_base(
			Span<byte> public_key, 
			ReadOnlySpan<byte> private_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_easy))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_easy(
			Span<byte> ciphertext, 
			ReadOnlySpan<byte> plaintext,
			ulong plaintext_len, 
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> public_key, 
			ReadOnlySpan<byte> private_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_open_easy))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_open_easy(
			Span<byte> plaintext, 
			ReadOnlySpan<byte> ciphertext,
			ulong ciphertext_len, 
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> public_key, 
			ReadOnlySpan<byte> private_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_detached))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_detached(
			Span<byte> ciphertext,
			Span<byte> mac,
			ReadOnlySpan<byte> plaintext,
			ulong plaintext_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> public_key,
			ReadOnlySpan<byte> private_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_open_detached))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_open_detached(
			Span<byte> plaintext,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> mac,
			ulong ciphertext_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> public_key,
			ReadOnlySpan<byte> private_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_beforenm))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_beforenm(
			Span<byte> shared_key, 
			ReadOnlySpan<byte> public_key,
			ReadOnlySpan<byte> private_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_easy_afternm))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_easy_afternm(
			Span<byte> ciphertext,
			ReadOnlySpan<byte> plaintext,
			ulong plaintext_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> shared_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_open_easy_afternm))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_open_easy_afternm(
			Span<byte> plaintext,
			ReadOnlySpan<byte> ciphertext,
			ulong ciphertext_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> shared_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_detached_afternm))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_detached_afternm(
			Span<byte> ciphertext,
			Span<byte> mac,
			ReadOnlySpan<byte> plaintext,
			ulong plaintext_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> shared_key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_open_detached_afternm))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_open_detached_afternm(
			Span<byte> plaintext,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> mac,
			ulong ciphertext_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> shared_key);

		// crypto_box_seal
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_seal))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_seal(
			Span<byte> ciphertext,
			ReadOnlySpan<byte> plaintext,
			ulong plaintext_len,
			ReadOnlySpan<byte> public_key);

		// crypto_box_seal_open
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_box_seal_open))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_box_seal_open(
			Span<byte> plaintext,
			ReadOnlySpan<byte> ciphertext,
			ulong ciphertext_len,
			ReadOnlySpan<byte> public_key,
			ReadOnlySpan<byte> private_key);

	}
}
