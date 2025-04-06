using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_memzero))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial void sodium_memzero(Span<byte> buf, nuint len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_memzero))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial void sodium_memzero(nint buf, nuint len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_mlock))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_mlock(nint address, nuint len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_munlock))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_munlock(nint address, nuint len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_malloc))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static unsafe partial nint sodium_malloc(nuint size);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_free))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial void sodium_free(nint buf);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_allocarray))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static unsafe partial nint sodium_allocarray(nuint count, nuint size);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_mprotect_readonly))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_mprotect_readonly(nint buf);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_mprotect_readwrite))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_mprotect_readwrite(nint buf);
	}
}
