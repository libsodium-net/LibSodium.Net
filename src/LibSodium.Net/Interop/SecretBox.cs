using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		internal const int crypto_secretbox_KEYBYTES = 32;
		internal const int crypto_secretbox_NONCEBYTES = 24;
		internal const int crypto_secretbox_MACBYTES = 16;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretbox_easy))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_secretbox_easy(
			Span<byte> ciphertext, ReadOnlySpan<byte> plaintext,
			ulong plaintext_len, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretbox_open_easy))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial	int crypto_secretbox_open_easy(
			Span<byte> plaintext, ReadOnlySpan<byte> ciphertext,
			ulong ciphertext_len, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretbox_detached))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_secretbox_detached(
			Span<byte> ciphertext, Span<byte> mac,
			ReadOnlySpan<byte> plaintext,ulong plaintext_len,
			ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretbox_open_detached))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_secretbox_open_detached(
			Span<byte> plaintext, ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> mac, ulong cipher_len,
			ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key);
	}
}
