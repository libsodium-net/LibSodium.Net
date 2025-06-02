using System;
using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides low-level scalar multiplication on Curve25519.
	/// This class exposes the <c>crypto_scalarmult</c> and <c>crypto_scalarmult_base</c> functions from libsodium.
	/// </summary>
	public static class CryptoScalarMult
	{
		/// <summary>
		/// Length of a Curve25519 private key (scalar) in bytes (32).
		/// </summary>
		public const int PrivateKeyLen = 32;

		/// <summary>
		/// Length of a Curve25519 public key (point) in bytes (32).
		/// </summary>
		public const int PublicKeyLen = 32;

		/// <summary>
		/// Computes the scalar multiplication of a private scalar and a public point on Curve25519.
		/// </summary>
		/// <param name="sharedPoint">The output buffer where the result (32 bytes) will be stored.</param>
		/// <param name="privateKey">The private scalar (32 bytes).</param>
		/// <param name="publicKey">The public point (32 bytes).</param>
		/// <exception cref="ArgumentException">Thrown if any input or output buffer has incorrect length.</exception>
		/// <exception cref="LibSodiumException">Thrown if the operation fails.</exception>
		/// <remarks>
		/// This method wraps <c>crypto_scalarmult</c>. Do not use the output directly as a symmetric key.
		/// </remarks>
		public static void Compute(Span<byte> sharedPoint, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
		{
			if (sharedPoint.Length != PublicKeyLen)
				throw new ArgumentException($"Output must be {PublicKeyLen} bytes.", nameof(sharedPoint));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes.", nameof(privateKey));
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes.", nameof(publicKey));

			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_scalarmult(sharedPoint, privateKey, publicKey) != 0)
				throw new LibSodiumException("crypto_scalarmult failed.");
		}

		/// <summary>
		/// Computes the scalar multiplication of a private scalar and a public point on Curve25519.
		/// </summary>
		/// <param name="sharedPoint">The output buffer where the result (32 bytes) will be stored.</param>
		/// <param name="privateKey">The private scalar (32 bytes).</param>
		/// <param name="publicKey">The public point (32 bytes).</param>
		/// <exception cref="ArgumentException">Thrown if any input or output buffer has incorrect length.</exception>
		/// <exception cref="LibSodiumException">Thrown if the operation fails.</exception>
		/// <remarks>
		/// This method wraps <c>crypto_scalarmult</c>. Do not use the output directly as a symmetric key.
		/// </remarks>
		public static void Compute(Span<byte> sharedPoint, SecureMemory<byte> privateKey, ReadOnlySpan<byte> publicKey)
		{
			Compute(sharedPoint, privateKey.AsReadOnlySpan(), publicKey);
		}

		/// <summary>
		/// Computes the public key corresponding to a private scalar on Curve25519.
		/// </summary>
		/// <param name="publicKey">The output buffer where the public key (32 bytes) will be stored.</param>
		/// <param name="privateKey">The private scalar (32 bytes).</param>
		/// <exception cref="ArgumentException">Thrown if any buffer has incorrect length.</exception>
		/// <exception cref="LibSodiumException">Thrown if the operation fails.</exception>
		/// <remarks>
		/// This method wraps <c>crypto_scalarmult_base</c>.
		/// </remarks>
		public static void CalculatePublicKey(Span<byte> publicKey, ReadOnlySpan<byte> privateKey)
		{
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes.", nameof(publicKey));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes.", nameof(privateKey));

			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_scalarmult_base(publicKey, privateKey) != 0)
				throw new LibSodiumException("crypto_scalarmult_base failed.");
		}

		/// <summary>
		/// Computes the public key corresponding to a private scalar on Curve25519.
		/// </summary>
		/// <param name="publicKey">The output buffer where the public key (32 bytes) will be stored.</param>
		/// <param name="privateKey">The private scalar (32 bytes).</param>
		/// <exception cref="ArgumentException">Thrown if any buffer has incorrect length.</exception>
		/// <exception cref="LibSodiumException">Thrown if the operation fails.</exception>
		/// <remarks>
		/// This method wraps <c>crypto_scalarmult_base</c>.
		/// </remarks>
		public static void CalculatePublicKey(Span<byte> publicKey, SecureMemory<byte> privateKey)
		{
			CalculatePublicKey(publicKey, privateKey.AsReadOnlySpan());
		}
	}
}
