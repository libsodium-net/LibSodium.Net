using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_pad))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_pad(
			out nuint padded_len, Span<byte> buffer,
			nuint unpadded_len, nuint block_size, nuint max_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(sodium_unpad))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int sodium_unpad(out nint unpadded_len, Span<byte> buffer,
				 nuint padded_len, nuint block_size);
	}
}
