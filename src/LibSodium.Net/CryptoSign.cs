using LibSodium.Interop;
using LibSodium.LowLevel;

namespace LibSodium
{
	/// <summary>
	/// Provides digital signature functionality using Ed25519, as implemented by libsodium.
	/// </summary>
	public static class CryptoSign
	{
		/// <summary>
		/// Length in bytes of a public key (32).
		/// </summary>
		public const int PublicKeyLen = Native.CRYPTO_SIGN_PUBLICKEYBYTES;

		/// <summary>
		/// Length in bytes of a private (secret) key (64).
		/// </summary>
		public const int PrivateKeyLen = Native.CRYPTO_SIGN_SECRETKEYBYTES;

		/// <summary>
		/// Length in bytes of a signature (64).
		/// </summary>
		public const int SignatureLen = Native.CRYPTO_SIGN_BYTES;

		/// <summary>
		/// Length in bytes of a seed used to generate key pairs deterministically.
		/// </summary>
		public const int SeedLen = Native.CRYPTO_SIGN_SEEDBYTES;

		/// <summary>
		/// Represents the length, in bytes, of the state buffer used in cryptographic signing operations.
		/// </summary>
		/// <remarks>This value is determined by the underlying native cryptographic library and is used to allocate
		/// buffers for signing state during incremental cryptographic operations.</remarks>
		internal static readonly int StateLen = (int) Native.crypto_sign_statebytes();

		/// <summary>
		/// Generates a new Ed25519 public/private key pair.
		/// </summary>
		/// <param name="publicKey">A span where the generated public key will be stored (must be <see cref="PublicKeyLen"/> bytes).</param>
		/// <param name="privateKey">A span where the generated private key will be stored (must be <see cref="PrivateKeyLen"/> bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if key pair generation fails.</exception>
		public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey)
		{
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(publicKey));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes long.", nameof(privateKey));
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_sign_keypair(publicKey, privateKey);
			if (result != 0)
				throw new LibSodiumException("Failed to generate key pair.");
		}

		/// <summary>
		/// Generates a new Ed25519 public/private key pair.
		/// </summary>
		/// <param name="publicKey">A span where the generated public key will be stored (must be <see cref="PublicKeyLen"/> bytes).</param>
		/// <param name="privateKey">A span where the generated private key will be stored (must be <see cref="PrivateKeyLen"/> bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if key pair generation fails.</exception>
		public static void GenerateKeyPair(Span<byte> publicKey, SecureMemory<byte> privateKey)
		{
			GenerateKeyPair(publicKey, privateKey.AsSpan());
		}

		/// <summary>
		/// Generates a Ed25519 public/private key pair from a seed deterministically.
		/// </summary>
		/// <param name="publicKey">A span where the generated public key will be stored (must be <see cref="PublicKeyLen"/> bytes).</param>
		/// <param name="secretKey">A span where the generated private key will be stored (must be <see cref="PrivateKeyLen"/> bytes).</param>
		/// <param name="seed">A seed used for key generation (must be <see cref="SeedLen"/> bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if key pair generation fails.</exception>
		public static void GenerateKeyPairDeterministically(
			Span<byte> publicKey,
			Span<byte> secretKey,
			ReadOnlySpan<byte> seed)
		{
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(publicKey));
			if (secretKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Secret key must be {PrivateKeyLen} bytes long.", nameof(secretKey));
			if (seed.Length != SeedLen)
				throw new ArgumentException($"Seed must be {SeedLen} bytes long.", nameof(seed));
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_sign_seed_keypair(publicKey, secretKey, seed);
			if (result != 0)
				throw new LibSodiumException("Failed to generate key pair.");
		}

		/// <summary>
		/// Generates a Ed25519 public/private key pair from a seed deterministically.
		/// </summary>
		/// <param name="publicKey">A span where the generated public key will be stored (must be <see cref="PublicKeyLen"/> bytes).</param>
		/// <param name="secretKey">A span where the generated private key will be stored (must be <see cref="PrivateKeyLen"/> bytes).</param>
		/// <param name="seed">A seed used for key generation (must be <see cref="SeedLen"/> bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if key pair generation fails.</exception>
		public static void GenerateKeyPairDeterministically(
			Span<byte> publicKey,
			SecureMemory<byte> secretKey,
			SecureMemory<byte> seed)
		{
			GenerateKeyPairDeterministically(publicKey, secretKey.AsSpan(), seed.AsReadOnlySpan());
		}

		/// <summary>
		/// Creates a Ed25519 signature for the given message using the provided private key.
		/// </summary>
		/// <param name="message">The message to be signed.</param>
		/// <param name="signature">A span to store the Ed25519 signature (must be at least <see cref="SignatureLen"/> bytes).</param>
		/// <param name="privateKey">The Ed25519 private key to sign with (must be <see cref="PrivateKeyLen"/> bytes).</param>
		/// <returns>A slice of the signature span containing the actual signature.</returns>
		/// <exception cref="ArgumentException">Thrown if the signature or private key length is incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if the signing operation fails.</exception>
		public static Span<byte> Sign(
			ReadOnlySpan<byte> message,
			Span<byte> signature,
			ReadOnlySpan<byte> privateKey)
		{
			if (signature.Length < SignatureLen)
				throw new ArgumentException($"Signature buffer must be at least {SignatureLen} bytes long.", nameof(signature));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes long.", nameof(privateKey));
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_sign_detached(signature, out var signatureLen, message, (ulong)message.Length, privateKey);
			if (result != 0)
				throw new LibSodiumException("Failed to sign message.");

			return signature.Slice(0, (int)signatureLen);
		}

		/// <summary>
		/// Creates an Ed25519 signature for the given message using the provided private key.
		/// </summary>
		/// <param name="message">The message to be signed.</param>
		/// <param name="signature">A span to store the Ed25519 signature (must be at least <see cref="SignatureLen"/> bytes).</param>
		/// <param name="privateKey">The Ed25519 private key to sign with (must be <see cref="PrivateKeyLen"/> bytes).</param>
		/// <returns>A slice of the signature span containing the actual signature.</returns>
		/// <exception cref="ArgumentException">Thrown if the signature or private key length is incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if the signing operation fails.</exception>
		public static Span<byte> Sign(
			ReadOnlySpan<byte> message,
			Span<byte> signature,
			SecureMemory<byte> privateKey)
		{
			return Sign(message, signature, privateKey.AsReadOnlySpan());
		}

		/// <summary>
		/// Verifies an Ed25519 signature against a given message and public key.
		/// </summary>
		/// <param name="message">The original message.</param>
		/// <param name="signature">The Ed25519 signature to verify (must be <see cref="SignatureLen"/> bytes).</param>
		/// <param name="publicKey">The Ed25519 public key used to verify the signature (must be <see cref="PublicKeyLen"/> bytes).</param>
		/// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
		/// <exception cref="ArgumentException">Thrown if the signature or public key length is incorrect.</exception>
		public static bool Verify(
			ReadOnlySpan<byte> message,
			ReadOnlySpan<byte> signature,
			ReadOnlySpan<byte> publicKey)
		{
			if (signature.Length != SignatureLen)
				throw new ArgumentException($"Signature must be {SignatureLen} bytes long.", nameof(signature));
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(publicKey));
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_sign_verify_detached(signature, message, (ulong)message.Length, publicKey);
			return result == 0;
		}


		/// <summary>
		/// Converts an Ed25519 public key (32 bytes) to a Curve25519 public key (32 bytes).
		/// </summary>
		/// <param name="curvePublicKey">The buffer where the resulting Curve25519 public key will be written. Must be 32 bytes.</param>
		/// <param name="edPublicKey">The source Ed25519 public key. Must be 32 bytes.</param>
		/// <exception cref="ArgumentException">Thrown if buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if the conversion fails.</exception>
		/// <remarks>
		/// The resulting Curve25519 public key can be used with <see cref="CryptoBox"/> and <see cref="CryptoKeyExchange"/> APIs.
		/// </remarks>
		public static void PublicKeyToCurve(Span<byte> curvePublicKey, ReadOnlySpan<byte> edPublicKey)
		{
			if (curvePublicKey.Length != CryptoBox.PublicKeyLen)
				throw new ArgumentException($"Curve25519 public key must be {CryptoBox.PublicKeyLen} bytes.", nameof(curvePublicKey));
			if (edPublicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Ed25519 public key must be {PublicKeyLen} bytes.", nameof(edPublicKey));

			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_sign_ed25519_pk_to_curve25519(curvePublicKey, edPublicKey) != 0)
				throw new LibSodiumException("Conversion from Ed25519 public key to Curve25519 failed.");
		}

		/// <summary>
		/// Converts an Ed25519 private key (64 bytes) to a Curve25519 private key (32 bytes).
		/// </summary>
		/// <param name="curvePrivateKey">The buffer where the resulting Curve25519 private key will be written. Must be 32 bytes.</param>
		/// <param name="edPrivateKey">The source Ed25519 private key. Must be 64 bytes.</param>
		/// <exception cref="ArgumentException">Thrown if buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if the conversion fails.</exception>
		/// <remarks>
		/// The resulting Curve25519 private key can be used with <see cref="CryptoBox"/> and <see cref="CryptoKeyExchange"/> APIs.
		/// </remarks>
		public static void PrivateKeyToCurve(Span<byte> curvePrivateKey, ReadOnlySpan<byte> edPrivateKey)
		{
			if (curvePrivateKey.Length != CryptoBox.PrivateKeyLen)
				throw new ArgumentException($"Curve25519 private key must be {CryptoBox.PrivateKeyLen} bytes.", nameof(curvePrivateKey));
			if (edPrivateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Ed25519 private key must be {PrivateKeyLen} bytes.", nameof(edPrivateKey));

			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_sign_ed25519_sk_to_curve25519(curvePrivateKey, edPrivateKey) != 0)
				throw new LibSodiumException("Conversion from Ed25519 private key to Curve25519 failed.");
		}

		/// <summary>
		/// Converts an Ed25519 private key (64 bytes) to a Curve25519 private key (32 bytes).
		/// </summary>
		/// <param name="curvePrivateKey">The buffer where the resulting Curve25519 private key will be written. Must be 32 bytes.</param>
		/// <param name="edPrivateKey">The source Ed25519 private key. Must be 64 bytes.</param>
		/// <exception cref="ArgumentException">Thrown if buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if the conversion fails.</exception>
		/// <remarks>
		/// The resulting Curve25519 private key can be used with <see cref="CryptoBox"/> and <see cref="CryptoKeyExchange"/> APIs.
		/// </remarks>
		public static void PrivateKeyToCurve(SecureMemory<byte> curvePrivateKey, SecureMemory<byte> edPrivateKey)
		{
			PrivateKeyToCurve(curvePrivateKey.AsSpan(), edPrivateKey.AsReadOnlySpan());
		}

		/// <summary>
		/// Creates an Ed25519ph incremental signing operation using the provided private key.
		/// The key is not copied or disposed. The caller is responsible for its lifecycle and protection.
		/// </summary>
		/// <param name="privateKey">The private key used for signing (64 bytes).</param>
		/// <returns>An incremental operation that produces a signature when finalized.</returns>

		public static ICryptoIncrementalOperation CreateIncrementalPreHashSign(ReadOnlyMemory<byte> privateKey)
		{
			return new CryptoSignIncremental(privateKey);
		}

		/// <summary>
		/// Creates an Ed25519ph incremental signing operation using a private key stored in secure memory.
		/// The key is used as-is and not disposed automatically. The caller retains ownership.
		/// </summary>
		/// <param name="privateKey">The Ed25519ph private key used for signing, stored in secure memory (64 bytes).</param>
		/// <returns>An incremental operation that produces a signature when finalized.</returns>

		public static ICryptoIncrementalOperation CreateIncrementalPreHashSign(SecureMemory<byte> privateKey)
		{
			return new CryptoSignIncremental(privateKey.AsReadOnlyMemory());
		}

		/// <summary>
		/// Creates an Ed25519ph incremental verification operation using the given public key and signature.
		/// The result of the verification is written to the output span as a single byte: 1 for valid, 0 for invalid.
		/// </summary>
		/// <param name="publicKey">The Ed25519ph public key used to verify the signature (32 bytes).</param>
		/// <param name="signature">The expected Ed25519ph signature to verify against (64 bytes).</param>
		/// <returns>An incremental operation that validates the message on finalization.</returns>

		public static ICryptoIncrementalOperation CreateIncrementalPreHashVerify(ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> signature)
		{
			return new CryptoSignVerifyIncremental(publicKey, signature);
		}

		/// <summary>
		/// Signs the contents of a stream using the specified Ed25519ph private key and writes the Ed25519ph signature to the provided buffer.
		/// </summary>
		/// <param name="message">The input stream containing the message to sign.</param>
		/// <param name="signature">A buffer that will receive theEd25519ph signature. Must be at least 64 bytes.</param>
		/// <param name="privateKey">The Ed25519ph private key (64 bytes).</param>
		/// <returns>The portion of the signature buffer containing the resulting signature (64 bytes).</returns>

		public static Span<byte> PreHashSign(
			Stream message,
			Span<byte> signature,
			ReadOnlyMemory<byte> privateKey)
		{
			using (var incremental = CreateIncrementalPreHashSign(privateKey))
			{
				incremental.Compute(message, signature);
				return signature.Slice(0, SignatureLen);
			}
		}

		/// <summary>
		/// Signs the contents of a stream using a Ed25519ph private key stored in secure memory.
		/// </summary>
		/// <param name="message">The input stream containing the message to sign.</param>
		/// <param name="signature">A buffer that will receive the Ed25519ph signature. Must be at least 64 bytes.</param>
		/// <param name="privateKey">The Ed25519ph private key in secure memory (64 bytes).</param>
		/// <returns>The portion of the signature buffer containing the resulting signature (64 bytes).</returns>

		public static Span<byte> PreHashSign(
			Stream message,
			Span<byte> signature,
			SecureMemory<byte> privateKey)
		{
			return PreHashSign(message, signature, privateKey.AsReadOnlyMemory());
		}

		/// <summary>
		/// Asynchronously signs the contents of a stream using the specified private key and writes the Ed25519ph signature to the provided buffer.
		/// </summary>
		/// <param name="message">The input stream containing the message to sign.</param>
		/// <param name="signature">A memory buffer that will receive the Ed25519ph signature. Must be at least 64 bytes.</param>
		/// <param name="privateKey">The Ed25519ph private key (64 bytes).</param>
		/// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
		/// <returns>The portion of the signature buffer containing the resulting signature (64 bytes).</returns>

		public static async Task<Memory<byte>> PreHashSignAsync(
			Stream message,
			Memory<byte> signature,
			ReadOnlyMemory<byte> privateKey,
			CancellationToken cancellationToken = default)
		{
			using (var incremental = CreateIncrementalPreHashSign(privateKey))
			{
				await incremental.ComputeAsync(message, signature, cancellationToken).ConfigureAwait(false);
				return signature.Slice(0, SignatureLen);
			}
		}

		/// <summary>
		/// Asynchronously signs the contents of a stream using a private key stored in secure memory and Ed25519ph.
		/// </summary>
		/// <param name="message">The input stream containing the message to sign.</param>
		/// <param name="signature">A memory buffer that will receive the Ed25519ph signature. Must be at least 64 bytes.</param>
		/// <param name="privateKey">The Ed25519ph private key in secure memory (64 bytes).</param>
		/// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
		/// <returns>The portion of the signature buffer containing the resulting signature (64 bytes).</returns>

		public static async Task<Memory<byte>> PreHashSignAsync(
			Stream message,
			Memory<byte> signature,
			SecureMemory<byte> privateKey,
			CancellationToken cancellationToken = default)
		{
			return await PreHashSignAsync(message, signature, privateKey.AsReadOnlyMemory(), cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Verifies the signature of a stream using the specified public key and Ed25519ph.
		/// </summary>
		/// <param name="message">The input stream containing the message to verify.</param>
		/// <param name="signature">The Ed25519ph signature to verify (64 bytes).</param>
		/// <param name="publicKey">The Ed25519ph public key (32 bytes).</param>
		/// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>

		public static bool PreHashVerify(
			Stream message,
			ReadOnlyMemory<byte> signature,
			ReadOnlyMemory<byte> publicKey)
		{
			using (var incremental = CreateIncrementalPreHashVerify(publicKey, signature))
			{
				Span<byte> result = stackalloc byte[1];
				incremental.Compute(message, result);
				return result[0] == (byte)1; // 1 indicates valid signature
			}
		}

		/// <summary>
		/// Asynchronously verifies the signature of a stream using the specified public key and Ed25519ph.
		/// </summary>
		/// <param name="message">The input stream containing the message to verify.</param>
		/// <param name="signature">The Ed25519ph signature to verify (64 bytes).</param>
		/// <param name="publicKey">The Ed25519ph public key (32 bytes).</param>
		/// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
		/// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>

		public static async Task<bool> PreHashVerifyAsync(
			Stream message,
			ReadOnlyMemory<byte> signature,
			ReadOnlyMemory<byte> publicKey,
			CancellationToken cancellationToken = default)
		{
			using (var incremental = CreateIncrementalPreHashVerify(publicKey, signature))
			{
				var result = new byte[1];
				await incremental.ComputeAsync(message, result, cancellationToken).ConfigureAwait(false);
				return result[0] == (byte) 1; // 1 indicates valid signature
			}
		}
	}
}
