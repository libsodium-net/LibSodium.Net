using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		internal const int CRYPTO_CORE_HCHACHA20_INPUTBYTES = 16;
		internal const int CRYPTO_CORE_HCHACHA20_KEYBYTES = 32;
		internal const int CRYPTO_CORE_HCHACHA20_OUTPUTBYTES = 32;
		internal const int CRYPTO_CORE_HCHACHA20_CONSTBYTES = 16;


		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_core_hchacha20))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_core_hchacha20(
			Span<byte> output,
			ReadOnlySpan<byte> input,
			ReadOnlySpan<byte> key,
			ReadOnlySpan<byte> constant);

	}
}
