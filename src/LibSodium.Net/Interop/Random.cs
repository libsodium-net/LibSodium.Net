using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		internal const int RANDOMBYTES_SEEDBYTES = 32;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(randombytes_random))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial uint randombytes_random();

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(randombytes_uniform))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial uint randombytes_uniform(uint upper_bound);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(randombytes_buf))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial void randombytes_buf(Span<byte> buffer, nuint size);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(randombytes_buf_deterministic))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial void randombytes_buf_deterministic(Span<byte> buffer, nuint size, ReadOnlySpan<byte> seed);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(randombytes_close))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int randombytes_close();

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(randombytes_stir))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial void randombytes_stir();
	}
}
