using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		private const string LibSodiumNativeLibraryName = "libsodium";

		// Corresponding to LIBSODIUM_VERSION_MAJOR
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_init();

		// Corresponding to LIBSODIUM_VERSION_MINOR
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_set_misuse_handler))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_set_misuse_handler(Action handler);

	}
}
