using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_BYTES_MIN = 16;
		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_BYTES_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_PASSWD_MIN = 0;
		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_PASSWD_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES = 32;
		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102;
		public const string CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX = "$7$";

		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_MIN = 32768;
		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_MIN = 16777216;
		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288;
		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;

		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE = 33554432;
		public const int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE = 1073741824;


		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_pwhash_scryptsalsa208sha256))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_pwhash_scryptsalsa208sha256(
			Span<byte> key,
			ulong keyLen,
			ReadOnlySpan<byte> password,
			ulong passwordLen,
			ReadOnlySpan<byte> salt,
			ulong opsLimit,
			nuint memLimit);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_pwhash_scryptsalsa208sha256_str))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_pwhash_scryptsalsa208sha256_str(
			Span<byte> str,
			ReadOnlySpan<byte> password,
			ulong passwordLen,
			ulong opsLimit,
			nuint memLimit);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_pwhash_scryptsalsa208sha256_str_verify))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_pwhash_scryptsalsa208sha256_str_verify(
			ReadOnlySpan<byte> hashedPassword,
			ReadOnlySpan<byte> password,
			ulong passwordLen);
	}
}
