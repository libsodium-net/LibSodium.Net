using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		public const int CRYPTO_PWHASH_ALG_ARGON2I13 = 1;
		public const int CRYPTO_PWHASH_ALG_ARGON2ID13 = 2;
		public const int CRYPTO_PWHASH_ALG_DEFAULT = CRYPTO_PWHASH_ALG_ARGON2ID13;

		public const int CRYPTO_PWHASH_BYTES_MIN = 16;
		public const int CRYPTO_PWHASH_BYTES_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_PASSWD_MIN = 0;
		public const int CRYPTO_PWHASH_PASSWD_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_SALTBYTES = 16;
		public const int CRYPTO_PWHASH_STRBYTES = 128;

		public const string CRYPTO_PWHASH_STRPREFIX = "$argon2id$";

		public const int CRYPTO_PWHASH_OPSLIMIT_MIN = 1;
		public const int CRYPTO_PWHASH_OPSLIMIT_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_MEMLIMIT_MIN = 8192;
		public const int CRYPTO_PWHASH_MEMLIMIT_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE = 2;
		public const int CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE = 64 * 1024 * 1024; // 64 MB

		public const int CRYPTO_PWHASH_OPSLIMIT_MODERATE = 3;
		public const int CRYPTO_PWHASH_MEMLIMIT_MODERATE = 256 * 1024 * 1024; // 256 MB

		public const int CRYPTO_PWHASH_OPSLIMIT_SENSITIVE = 4;
		public const int CRYPTO_PWHASH_MEMLIMIT_SENSITIVE = 1024 * 1024 * 1024; // 1 GB

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_pwhash))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_pwhash(
			Span<byte> key,
			ulong output_len,
			ReadOnlySpan<byte> password,
			ulong password_len,
			ReadOnlySpan<byte> salt,
			ulong opsLimit,
			nuint memLimit,
			int algorithm);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_pwhash_str))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_pwhash_str(
			Span<byte> output, 
			ReadOnlySpan<byte> password, 
			ulong password_len, 
			ulong opsLimit,
			nuint memLimit 
		);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_pwhash_str_verify))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_pwhash_str_verify(
			ReadOnlySpan<byte> hashed_password,
			ReadOnlySpan<byte> password,
			ulong passwordLen
		);

	}
}
