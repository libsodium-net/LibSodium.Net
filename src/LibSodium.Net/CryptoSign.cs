using LibSodium.Interop;

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
		/// Creates a signature for the given message using the provided private key.
		/// </summary>
		/// <param name="message">The message to be signed.</param>
		/// <param name="signature">A span to store the signature (must be at least <see cref="SignatureLen"/> bytes).</param>
		/// <param name="privateKey">The private key to sign with (must be <see cref="PrivateKeyLen"/> bytes).</param>
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
		/// Verifies a signature against a given message and public key.
		/// </summary>
		/// <param name="message">The original message.</param>
		/// <param name="signature">The signature to verify (must be <see cref="SignatureLen"/> bytes).</param>
		/// <param name="publicKey">The public key used to verify the signature (must be <see cref="PublicKeyLen"/> bytes).</param>
		/// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
		/// <exception cref="ArgumentException">Thrown if the signature or public key length is incorrect.</exception>
		public static bool TryVerify(
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
		/// Verifies a signature against a given message and public key.
		/// Throws if the signature is invalid.
		/// </summary>
		/// <param name="message">The original message.</param>
		/// <param name="signature">The signature to verify (must be <see cref="SignatureLen"/> bytes).</param>
		/// <param name="publicKey">The public key used to verify the signature (must be <see cref="PublicKeyLen"/> bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the signature or public key length is incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if the signature is invalid.</exception>
		public static void Verify(
			ReadOnlySpan<byte> message,
			ReadOnlySpan<byte> signature,
			ReadOnlySpan<byte> publicKey)
		{
			if (TryVerify(message, signature, publicKey)) return;
			throw new LibSodiumException("Failed to verify signature.");
		}

	}
}
