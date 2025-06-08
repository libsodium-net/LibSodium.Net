using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop;

/// <summary>
/// Low‑level P/Invoke declarations for Ristretto255 “core” and “scalarmult” symbols.
/// These signatures are <c>internal</c>, allocation‑free and fully <see cref="Span{T}"/>‑based—no pointers or unsafe code.
/// </summary>
internal static partial class Native
{
	private const string Sodium = "libsodium";

	// Constant lengths (bytes)
	public const int CRYPTO_CORE_RISTRETTO255_BYTES = 32; // Point length
	public const int crypto_core_ristretto255_HASHBYTES = 64; // Hash length
	public const int CRYPTO_CORE_RISTRETTO255_SCALARBYTES = 32; // Scalar length
	public const int CRYPTO_CORE_RISTRETTO255_NONREDUCEDSCALARBYTES = 64; // Non-reduced scalar length

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_is_valid_point))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_core_ristretto255_is_valid_point(ReadOnlySpan<byte> p);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_random))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_core_ristretto255_random(Span<byte> p);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_from_hash))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_core_ristretto255_from_hash(
		Span<byte> p,            
		ReadOnlySpan<byte> h);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_scalarmult_ristretto255))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_scalarmult_ristretto255(
		Span<byte> q,               // out
		ReadOnlySpan<byte> n,       // scalar (32 B)
		ReadOnlySpan<byte> p);      // point  (32 B)

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_scalarmult_ristretto255_base))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_scalarmult_ristretto255_base(
		Span<byte> q,               // out
		ReadOnlySpan<byte> n);      // scalar (32 B)

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_add))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_core_ristretto255_add(
		Span<byte> r,
		ReadOnlySpan<byte> p,
		ReadOnlySpan<byte> q);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_sub))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_core_ristretto255_sub(
		Span<byte> r,
		ReadOnlySpan<byte> p,
		ReadOnlySpan<byte> q);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_scalar_random))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_core_ristretto255_scalar_random(Span<byte> r);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_scalar_reduce))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_core_ristretto255_scalar_reduce(
		Span<byte> r, 
		ReadOnlySpan<byte> s);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_scalar_invert))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial int crypto_core_ristretto255_scalar_invert(
		Span<byte> recip, 
		ReadOnlySpan<byte> s);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_scalar_negate))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial void crypto_core_ristretto255_scalar_negate(Span<byte> neg, ReadOnlySpan<byte> s);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_scalar_complement))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial void crypto_core_ristretto255_scalar_complement(Span<byte> comp, ReadOnlySpan<byte> s);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_scalar_add))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial void crypto_core_ristretto255_scalar_add(
		Span<byte> z,
		ReadOnlySpan<byte> x,
		ReadOnlySpan<byte> y);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_scalar_sub))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial void crypto_core_ristretto255_scalar_sub(
		Span<byte> z,
		ReadOnlySpan<byte> x,
		ReadOnlySpan<byte> y);

	[LibraryImport(Sodium, EntryPoint = nameof(crypto_core_ristretto255_scalar_mul))]
	[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
	internal static partial void crypto_core_ristretto255_scalar_mul(
		Span<byte> z,
		ReadOnlySpan<byte> x,
		ReadOnlySpan<byte> y);





}
