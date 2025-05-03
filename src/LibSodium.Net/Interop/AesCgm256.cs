using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		internal const int CRYPTO_AEAD_AES256GCM_KEYBYTES = 32;
		internal const int CRYPTO_AEAD_AES256GCM_NPUBBYTES = 12;
		internal const int CRYPTO_AEAD_AES256GCM_ABYTES = 16;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_aes256gcm_encrypt))]
		internal static partial int crypto_aead_aes256gcm_encrypt(
			Span<byte> ciphertext,
			out ulong ciphertext_len,
			ReadOnlySpan<byte> plaintext,
			ulong plaintext_len,
			ReadOnlySpan<byte> aad,
			ulong aad_len,
			nuint nsec,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_aes256gcm_decrypt))]
		internal static partial int crypto_aead_aes256gcm_decrypt(
			Span<byte> plaintext,
			out ulong plaintext_len,
			nuint nsec,
			ReadOnlySpan<byte> ciphertext,
			ulong ciphertext_len,
			ReadOnlySpan<byte> aad,
			ulong aad_len,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_aes256gcm_encrypt_detached))]
		internal static partial int crypto_aead_aes256gcm_encrypt_detached(
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

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_aead_aes256gcm_decrypt_detached))]
		internal static partial int crypto_aead_aes256gcm_decrypt_detached(
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
