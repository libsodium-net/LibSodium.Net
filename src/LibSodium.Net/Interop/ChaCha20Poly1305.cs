using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		// keylen: 32
		internal const int CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = 32;
		// nonce: 12
		internal const int CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES = 8;
		// mac: 16
		internal const int CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = 16;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_chacha20poly1305_encrypt))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_aead_chacha20poly1305_encrypt(
			Span<byte> ciphertext,
			out ulong ciphertext_len,
			ReadOnlySpan<byte> plaintext,
			ulong plaintext_len,
			ReadOnlySpan<byte> additional_data,
			ulong additional_data_len,
			nuint nsec, // always null
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_chacha20poly1305_decrypt))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_aead_chacha20poly1305_decrypt(
			Span<byte> plaintext,
			out ulong plaintext_len,
			nuint nsec, // always null
			ReadOnlySpan<byte> ciphertext,
			ulong ciphertext_len,
			ReadOnlySpan<byte> additional_data,
			ulong additional_data_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_chacha20poly1305_encrypt_detached))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_aead_chacha20poly1305_encrypt_detached(
			Span<byte> ciphertext,
			Span<byte> mac,
			out ulong mac_len,
			ReadOnlySpan<byte> message,
			ulong message_len,
			ReadOnlySpan<byte> additional_data,
			ulong additional_data_len,
			nuint nsec, // always null
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_chacha20poly1305_decrypt_detached))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_aead_chacha20poly1305_decrypt_detached(
			Span<byte> plaintext,
			nuint nsec,
			ReadOnlySpan<byte> ciphertext,
			ulong ciphertext_len,
			ReadOnlySpan<byte> mac,
			ReadOnlySpan<byte> additional_data,
			ulong additional_data_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);
	}
}
