using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_scalarmult))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_scalarmult(
			Span<byte> q,
			ReadOnlySpan<byte> n,
			ReadOnlySpan<byte> p);

	}
}
