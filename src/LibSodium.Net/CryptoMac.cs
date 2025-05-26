using System.Diagnostics.CodeAnalysis;
using LibSodium.LowLevel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using LibSodium;

namespace LibSodium;

/// <summary>
/// Provides a generic interface for computing and verifying HMACs using different SHA-2 variants.
/// </summary>
/// <typeparam name="T">The HMAC implementation (e.g. <see cref="LowLevel.HmacSha256"/>).</typeparam>
internal static class CryptoMac<T> where T : struct, IMac
{
	private const int DefaultBufferLen = 8192;
	public static readonly int MacLen = T.MacLen;
	public static readonly int KeyLen = T.KeyLen;

	public static int ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> hash)
	{

		if (key.Length != T.KeyLen)
			throw new ArgumentException($"Key must be exactly {T.KeyLen} bytes.", nameof(key));
		if (hash.Length != T.MacLen)
			throw new ArgumentException($"Hash buffer must be exactly {T.MacLen} bytes.", nameof(hash));
		LibraryInitializer.EnsureInitialized();
		if (T.ComputeMac(hash, source, key) != 0)
			throw new LibSodiumException("MAC computation failed.");
		return T.MacLen;
	}

	public static bool VerifyMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, ReadOnlySpan<byte> hash)
	{
		if (key.Length != T.KeyLen)
			throw new ArgumentException($"Key must be exactly {T.KeyLen} bytes.", nameof(key));
		if (hash.Length != T.MacLen)
			throw new ArgumentException($"Hash must be exactly {T.MacLen} bytes.", nameof(hash));
		LibraryInitializer.EnsureInitialized();
		return T.VerifyMac(hash, source, key) == 0;
	}

	/// <summary>
	/// Generates a random key suitable for the selected HMAC algorithm.
	/// </summary>
	public static void GenerateKey(Span<byte> key)
	{
		LibraryInitializer.EnsureInitialized();
		if (key.Length != T.KeyLen)
			throw new ArgumentException($"Key must be exactly {T.KeyLen} bytes.", nameof(key));

		T.GenerateKey(key);
	}

	/// <summary>
	/// Computes an HMAC hash from a stream.
	/// </summary>
	public static void ComputeMac(ReadOnlySpan<byte> key, Stream source, Span<byte> hash)
	{
		ArgumentNullException.ThrowIfNull(source);
		using (var incrementalHash = CreateIncrementalHash(key))
		{
			incrementalHash.Compute(source, hash);
		}
	}

	/// <summary>
	/// Verifies a hash against the contents of a stream.
	/// </summary>
	public static bool VerifyMac(ReadOnlySpan<byte> key, Stream source, ReadOnlySpan<byte> hash)
	{
		ArgumentNullException.ThrowIfNull(source);
		Span<byte> computed = stackalloc byte[T.MacLen];
		ComputeMac(key, source, computed);
		return computed.SequenceEqual(hash);
	}

	/// <summary>
	/// Asynchronously computes an MAC from a stream.
	/// </summary>
	public static async Task ComputeMacAsync(ReadOnlyMemory<byte> key, Stream source, Memory<byte> hash, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(source);
		using (var incrementalHash = CreateIncrementalHash(key.Span))
		{
			await incrementalHash.ComputeAsync(source, hash, cancellationToken).ConfigureAwait(false);
		}
	}

	/// <summary>
	/// Asynchronously verifies a hash against a stream.
	/// </summary>
	public static async Task<bool> VerifyMacAsync(ReadOnlyMemory<byte> key, Stream source, ReadOnlyMemory<byte> hash, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(source);
		LibraryInitializer.EnsureInitialized();
		byte[] computed = new byte[T.MacLen];
		await ComputeMacAsync(key, source, computed, cancellationToken).ConfigureAwait(false);
		return computed.AsSpan().SequenceEqual(hash.Span);
	}


	/// <summary>
	/// Creates an incremental hash instance using the specified key.
	/// </summary>
	/// <param name="key">A read-only span containing the key to initialize the hash. The key must be exactly <see cref="IMac.KeyLen"/> bytes in
	/// length.</param>
	/// <returns>An <see cref="ICryptoIncrementalHash"/> instance that can be used to compute the hash incrementally.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not exactly <see cref="IMac.KeyLen"/> bytes in length.</exception>
	public static ICryptoIncrementalHash CreateIncrementalHash(ReadOnlySpan<byte> key)
	{
		return new CryptoMacIncremental<T>(key);
	}
}
