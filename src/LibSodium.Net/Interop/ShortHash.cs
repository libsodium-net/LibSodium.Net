using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		public const int CRYPTO_SHORTHASH_BYTES = 8;
		public const int CRYPTO_SHORTHASH_KEYBYTES = 16;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_shorthash))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_shorthash(
			Span<byte> hash,                  
			ReadOnlySpan<byte> input,           
			ulong input_len,                 
			ReadOnlySpan<byte> key);
	}
}
