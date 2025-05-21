using System.Security.Cryptography;
using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides HKDF key derivation (RFC 5869) using SHA-256 or SHA-512.
	/// </summary>
	public static class HKDF
	{
		/// <summary>
		/// Length of the pseudorandom key (PRK) for SHA256 in bytes (32).
		/// </summary>
		public const int Sha256PrkLen = 32;

		/// <summary>
		/// Length of the pseudorandom key (PRK) for SHA256 in bytes (32).
		/// </summary>
		public const int Sha512PrkLen = 64;

		/// <summary>
		/// Minimum length of output key material (OKM) in bytes (4).
		/// </summary>
		public const int MinOkmLen = 4;

		/// <summary>
		/// Maximum length of output key material (OKM) for SHA256 in bytes (8160 = 32 * 255).
		/// </summary>
		public const int Sha256MaxOkmLen = 8160;

		/// <summary>
		/// Maximum length of output key material (OKM) for SHA512 in bytes (8160 = 64 * 255).
		/// </summary>
		public const int Sha512MaxOkmLen = 16320;


		internal static readonly int Sha256StateLen = (int)Native.crypto_kdf_hkdf_sha256_statebytes();
		internal static readonly int Sha512StateLen = (int)Native.crypto_kdf_hkdf_sha512_statebytes();



		/// <summary>
		/// Performs the extract step of HKDF (RFC 5869), using the specified hash algorithm.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Input keying material.</param>
		/// <param name="salt">Optional salt value (can be empty).</param>
		/// <param name="prk">Buffer to receive the pseudorandom key (32 bytes for SHA256 and 64 bytes for SHA512).</param>
		/// <exception cref="ArgumentException">Thrown if <paramref name="prk"/> is not exactly the required size.</exception>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>
		public static void Extract(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, Span<byte> prk)
		{
			int result = 0;
			switch (hashAlgorithmName.Name)
			{
				case nameof(HashAlgorithmName.SHA256):
					if (prk.Length != Sha256PrkLen) throw new ArgumentException($"PRK buffer must be exactly {Sha256PrkLen} bytes for SHA256.", nameof(prk));
					LibraryInitializer.EnsureInitialized();
					result = Native.crypto_kdf_hkdf_sha256_extract(prk, salt, (nuint)salt.Length, ikm, (nuint)ikm.Length); break;

				case nameof(HashAlgorithmName.SHA512):
					if (prk.Length != Sha512PrkLen) throw new ArgumentException($"PRK buffer must be exactly {Sha512PrkLen} bytes for SHA512.", nameof(prk));
					LibraryInitializer.EnsureInitialized();
					result = Native.crypto_kdf_hkdf_sha512_extract(prk, salt, (nuint)salt.Length, ikm, (nuint)ikm.Length); break;
				default:
					throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}");

			}
			if (result != 0)
				throw new LibSodiumException($"Failed to extract prk using hash algorithm {hashAlgorithmName.Name}");
		}

		/// <summary>
		/// Performs the expand step of HKDF (RFC 5869), using the specified hash algorithm.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="prk">Pseudorandom key obtained from the extract step (32 or 64 bytes).</param>
		/// <param name="okm">Output buffer to receive the derived keying material (4–8160 or 16320 bytes).</param>
		/// <param name="info">Optional context and application-specific information.</param>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="okm"/> is not in valid range.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="prk"/> is not valid size for the selected hash.</exception>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>
		public static void Expand(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> prk, Span<byte> okm, ReadOnlySpan<byte> info)
		{
			int result = 0;
			switch (hashAlgorithmName.Name)
			{
				case nameof(HashAlgorithmName.SHA256):
					if (okm.Length < MinOkmLen || okm.Length > Sha256MaxOkmLen)
						throw new ArgumentOutOfRangeException(nameof(okm), $"Output length must be between {MinOkmLen} and {Sha256MaxOkmLen} bytes for SHA256.");
					if (prk.Length != Sha256PrkLen)
						throw new ArgumentException($"PRK must be exactly {Sha256PrkLen} bytes for SHA256.", nameof(prk));
					LibraryInitializer.EnsureInitialized();
					result = Native.crypto_kdf_hkdf_sha256_expand(okm, (nuint)okm.Length, info, (nuint)info.Length, prk);
					break;
				case nameof(HashAlgorithmName.SHA512):
					if (okm.Length < MinOkmLen || okm.Length > Sha512MaxOkmLen)
						throw new ArgumentOutOfRangeException(nameof(okm), $"Output length must be between {MinOkmLen} and {Sha512MaxOkmLen} bytes for SHA512.");
					if (prk.Length != Sha512PrkLen)
						throw new ArgumentException($"PRK must be exactly {Sha512PrkLen} bytes for SHA512.", nameof(prk));
					LibraryInitializer.EnsureInitialized();
					result = Native.crypto_kdf_hkdf_sha512_expand(okm, (nuint)okm.Length, info, (nuint)info.Length, prk);
					break;
				default:
					throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}");
			}
			if (result != 0)
				throw new LibSodiumException($"Failed to expand using hash algorithm {hashAlgorithmName.Name}");
		}

		/// <summary>
		/// Derives key material from input key material in one step using HKDF (RFC 5869).
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Input keying material.</param>
		/// <param name="okm">Output buffer to receive the derived keying material (16–64 bytes).</param>
		/// <param name="salt">Optional salt value (can be empty).</param>
		/// <param name="info">Optional context and application-specific information.</param>
		/// <exception cref="ArgumentException">Thrown if <paramref name="okm"/> or internal buffers have invalid lengths.</exception>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>
		public static void DeriveKey(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> ikm, Span<byte> okm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
		{
			var prkLen = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Sha256PrkLen,
				nameof(HashAlgorithmName.SHA512) => Sha512PrkLen,
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};
			Span<byte> prk = stackalloc byte[prkLen];
			Extract(hashAlgorithmName, ikm, salt, prk);
			Expand(hashAlgorithmName, prk, okm, info);
		}

		/// <summary>
		/// Performs the extract step of HKDF (RFC 5869) using a stream as input keying material.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Stream of input keying material (IKM).</param>
		/// <param name="salt">Optional salt value (can be empty).</param>
		/// <param name="prk">Buffer to receive the pseudorandom key (32 bytes for SHA256 and 64 bytes for SHA512).</param>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="ikm"/> is null.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="prk"/> length is incorrect.</exception>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>
		public static void Extract(HashAlgorithmName hashAlgorithmName, Stream ikm, ReadOnlySpan<byte> salt, Span<byte> prk)
		{
			if (ikm == null) throw new ArgumentNullException(nameof(ikm));

			Span<byte> state = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => stackalloc byte[Sha256StateLen],
				nameof(HashAlgorithmName.SHA512) => stackalloc byte[Sha512StateLen],
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			int result;
			LibraryInitializer.EnsureInitialized();

			result = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_init(state, salt, (nuint)salt.Length),
				nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_init(state, salt, (nuint)salt.Length),
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			if (result != 0)
				throw new LibSodiumException($"Failed to initialize extract state for {hashAlgorithmName.Name}");

			byte[] buffer = new byte[4096];
			int read;
			while ((read = ikm.Fill(buffer, 0, buffer.Length)) > 0)
			{
				Span<byte> chunk = buffer.AsSpan(0, read);
				result = hashAlgorithmName.Name switch
				{
					nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_update(state, chunk, (nuint)chunk.Length),
					nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_update(state, chunk, (nuint)chunk.Length),
					_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
				};
				if (result != 0)
					throw new LibSodiumException($"Failed to update extract state for {hashAlgorithmName.Name}");
			}

			result = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_final(state, prk),
				nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_final(state, prk),
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			if (result != 0)
				throw new LibSodiumException($"Failed to finalize extract for {hashAlgorithmName.Name}");
		}

		/// <summary>
		/// Asynchronously performs the extract step of HKDF (RFC 5869) using a stream as input keying material.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Stream of input keying material (IKM).</param>
		/// <param name="salt">Optional salt value (can be empty).</param>
		/// <param name="prk">Buffer to receive the pseudorandom key (32 bytes for SHA256 and 64 bytes for SHA512).</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="ikm"/> is null.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="prk"/> length is incorrect.</exception>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>

		public static async Task ExtractAsync(HashAlgorithmName hashAlgorithmName, Stream ikm, ReadOnlyMemory<byte> salt, Memory<byte> prk, CancellationToken cancellationToken = default)
		{
			if (ikm == null) throw new ArgumentNullException(nameof(ikm));

			var state = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => new byte[Sha256StateLen],
				nameof(HashAlgorithmName.SHA512) => new byte[Sha512StateLen],
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			int result;
			LibraryInitializer.EnsureInitialized();

			result = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_init(state, salt.Span, (nuint)salt.Length),
				nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_init(state, salt.Span, (nuint)salt.Length),
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			if (result != 0)
				throw new LibSodiumException($"Failed to initialize extract state for {hashAlgorithmName.Name}");

			byte[] buffer = new byte[4096];
			int read;
			while ((read = await ikm.FillAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
			{
				result = hashAlgorithmName.Name switch
				{
					nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_update(state, buffer.AsSpan(0, read), (nuint)read),
					nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_update(state, buffer.AsSpan(0, read), (nuint)read),
					_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
				};
				if (result != 0)
					throw new LibSodiumException($"Failed to update extract state for {hashAlgorithmName.Name}");
			}

			result = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_final(state, prk.Span),
				nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_final(state, prk.Span),
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			if (result != 0)
				throw new LibSodiumException($"Failed to finalize extract for {hashAlgorithmName.Name}");
		}

		/// <summary>
		/// Derives key material from input key material in one step using HKDF (RFC 5869) from a stream.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Stream of input keying material.</param>
		/// <param name="okm">Buffer to receive the output keying material.</param>
		/// <param name="salt">Optional salt value.</param>
		/// <param name="info">Optional application-specific information.</param>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>

		public static void DeriveKey(HashAlgorithmName hashAlgorithmName, Stream ikm, Span<byte> okm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
		{
			var prkLen = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Sha256PrkLen,
				nameof(HashAlgorithmName.SHA512) => Sha512PrkLen,
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};
			Span<byte> prk = stackalloc byte[prkLen];
			Extract(hashAlgorithmName, ikm, salt, prk);
			Expand(hashAlgorithmName, prk, okm, info);
		}

		/// <summary>
		/// Asynchronously derives key material from input key material in one step using HKDF (RFC 5869) from a stream.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Stream of input keying material.</param>
		/// <param name="okm">Buffer to receive the output keying material.</param>
		/// <param name="salt">Optional salt value.</param>
		/// <param name="info">Optional application-specific information.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>
		public static async Task DeriveKeyAsync(HashAlgorithmName hashAlgorithmName, Stream ikm, Memory<byte> okm, ReadOnlyMemory<byte> salt, ReadOnlyMemory<byte> info, CancellationToken cancellationToken = default)
		{
			int prkLen = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Sha256PrkLen,
				nameof(HashAlgorithmName.SHA512) => Sha512PrkLen,
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};
			var prk = new byte[prkLen];
			await ExtractAsync(hashAlgorithmName, ikm, salt, prk, cancellationToken).ConfigureAwait(false);
			Expand(hashAlgorithmName, prk, okm.Span, info.Span);
		}
	}
}
