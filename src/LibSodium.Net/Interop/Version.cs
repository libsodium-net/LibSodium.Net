using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		internal const int LIBSODIUM_VERSION_MAJOR = 26;
		internal const int LIBSODIUM_VERSION_MINOR = 2;
		internal const string SODIUM_VERSION_STRING = "1.0.20";

		[LibraryImport("libsodium", EntryPoint = "sodium_library_version_major")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_library_version_major();

		[LibraryImport("libsodium", EntryPoint = "sodium_library_version_minor")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_library_version_minor();

		[LibraryImport("libsodium", EntryPoint = "sodium_version_string")]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nint sodium_version_string();
	}
}
