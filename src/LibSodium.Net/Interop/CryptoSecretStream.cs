using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretstream_xchacha20poly1305_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		public static partial int crypto_secretstream_xchacha20poly1305_statebytes();

		// 2) Generate a random 32-byte key
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretstream_xchacha20poly1305_keygen))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		public static partial void crypto_secretstream_xchacha20poly1305_keygen(
			Span<byte> key
		);

		// 3) init_push() - Start encrypting
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretstream_xchacha20poly1305_init_push))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		public static partial int crypto_secretstream_xchacha20poly1305_init_push(
			Span<byte> state,
			Span<byte> header,
			ReadOnlySpan<byte> key
		);

		// 4) push() - Encrypt (and authenticate) a chunk
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretstream_xchacha20poly1305_push))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		public static partial int crypto_secretstream_xchacha20poly1305_push(
			Span<byte> state,
			Span<byte> cipher,
			out ulong cipherLen,
			ReadOnlySpan<byte> message,
			ulong messageLen,
			nint ad,    // set to IntPtr.Zero when unused
			ulong adLen,
			byte tag
		);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretstream_xchacha20poly1305_push))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		public static partial int crypto_secretstream_xchacha20poly1305_push(
			Span<byte> state,
			Span<byte> cipher,
			out ulong cipherLen,
			ReadOnlySpan<byte> message,
			ulong messageLen,
			ReadOnlySpan<byte> ad,
			ulong adLen,
			byte tag
		);

		// 5) init_pull() - Start decrypting
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretstream_xchacha20poly1305_init_pull))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		public static partial int crypto_secretstream_xchacha20poly1305_init_pull(
			Span<byte> state,
			ReadOnlySpan<byte> header,
			ReadOnlySpan<byte> key
		);

		// 6) pull() - Decrypt (and verify) a chunk
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretstream_xchacha20poly1305_pull))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		public static partial int crypto_secretstream_xchacha20poly1305_pull(
			Span<byte> state,
			Span<byte> message,
			out ulong messageLen,
			out byte tag,
			ReadOnlySpan<byte> cipher,
			ulong cipherLen,
			nint ad,    // set to IntPtr.Zero when unused
			ulong adLen
		);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_secretstream_xchacha20poly1305_pull))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		public static partial int crypto_secretstream_xchacha20poly1305_pull(
			Span<byte> state,
			Span<byte> message,
			out ulong messageLen,
			out byte tag,
			ReadOnlySpan<byte> cipher,
			ulong cipherLen,
			ReadOnlySpan<byte> ad,    // set to IntPtr.Zero when unused
			ulong adLen
		);

		// Constants from libsodium's secretstream_xChaCha20poly1305.h
		internal const int CRYPTO_SECRET_STREAM_KEYBYTES = 32;   // crypto_secretstream_xChaCha20poly1305_KEYBYTES
		internal const int CRYPTO_SECRET_STREAM_HEADERBYTES = 24;   // crypto_secretstream_xChaCha20poly1305_HEADERBYTES
		internal const int CRYPTO_SECRET_STREAM_ABYTES = 17;   // crypto_secretstream_xChaCha20poly1305_ABYTES

		// Tag values
		internal const byte CRYPTO_SECRET_STREAM_TAG_MESSAGE = 0;
		internal const byte CRYPTO_SECRET_STREAM_TAG_PUSH = 1;
		internal const byte CRYPTO_SECRET_STREAM_TAG_REKEY = 2;
		internal const byte CRYPTO_SECRET_STREAM_TAG_FINAL = 3;
	}
}
