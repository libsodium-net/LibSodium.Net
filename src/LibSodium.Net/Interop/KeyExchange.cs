using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop;

internal static partial class Native
{
	public const int CRYPTO_KX_PUBLICKEYBYTES = 32;
	public const int CRYPTO_KX_SECRETKEYBYTES = 32;
	public const int CRYPTO_KX_SEEDBYTES = 32;
	public const int CRYPTO_KX_SESSIONKEYBYTES = 32;
	public const string CRYPTO_KX_PRIMITIVE = "x25519blake2b";

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kx_keypair))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_kx_keypair(
		Span<byte> pk, 
		Span<byte> sk);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kx_seed_keypair))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_kx_seed_keypair(
		Span<byte> pk, 
		Span<byte> sk, 
		ReadOnlySpan<byte> seed);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kx_client_session_keys))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_kx_client_session_keys(
		Span<byte> rx,
		Span<byte> tx,
		ReadOnlySpan<byte> client_pk,
		ReadOnlySpan<byte> client_sk,
		ReadOnlySpan<byte> server_pk);

	[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kx_server_session_keys))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_kx_server_session_keys(
		Span<byte> rx,
		Span<byte> tx,
		ReadOnlySpan<byte> server_pk,
		ReadOnlySpan<byte> server_sk,
		ReadOnlySpan<byte> client_pk);
}
