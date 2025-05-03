using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		// Mac size
		internal const int CRYPTO_AEAD_AEGIS256_ABYTES = 32;

		// key size
		internal const int CRYPTO_AEAD_AEGIS256_KEYBYTES = 32;

		// nonce size
		internal const int CRYPTO_AEAD_AEGIS256_NPUBBYTES = 32;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_aegis256_encrypt))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_aead_aegis256_encrypt(
			Span<byte> ciphertext,
			out ulong ciphertext_len,
			ReadOnlySpan<byte> plaintext,
			ulong plaintext_len,
			ReadOnlySpan<byte> aad,
			ulong aad_len,
			nuint nsec,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);


		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_aegis256_decrypt))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_aead_aegis256_decrypt(
			Span<byte> plaintext,
			out ulong plaintext_len,
			nuint nsec,
			ReadOnlySpan<byte> ciphertext,
			ulong ciphertext_len,
			ReadOnlySpan<byte> aad,
			ulong aad_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_aegis256_encrypt_detached))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_aead_aegis256_encrypt_detached(
			Span<byte> ciphertext,
			Span<byte> mac,
			out ulong mac_len,
			ReadOnlySpan<byte> plaintext,
			ulong plaintext_len,
			ReadOnlySpan<byte> aad,
			ulong aad_len,
			nuint nsec,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_aegis256_decrypt_detached))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_aead_aegis256_decrypt_detached(
			Span<byte> plaintext,
			nuint nsec,
			ReadOnlySpan<byte> ciphertext,
			ulong ciphertext_len,
			ReadOnlySpan<byte> mac,
			ReadOnlySpan<byte> aad,
			ulong aad_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

	}
}
