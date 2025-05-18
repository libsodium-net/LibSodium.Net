using LibSodium.Interop;

namespace LibSodium;

/// <summary>
/// Provides methods for secure, fast, and simple key exchange using libsodium's crypto_kx API.
/// Allows two parties to derive shared session keys securely.
/// </summary>
/// <remarks>
/// 🧂 Based on libsodium's crypto_kx API: https://doc.libsodium.org/key_exchange
/// </remarks>
public static class CryptoKeyExchange
{
	/// <summary>
	/// Length of the public key in bytes (32).
	/// </summary>
	public const int PublicKeyLen = Native.CRYPTO_KX_PUBLICKEYBYTES;

	/// <summary>
	/// Length of the secret (private) key in bytes (32).
	/// </summary>
	public const int SecretKeyLen = Native.CRYPTO_KX_SECRETKEYBYTES;

	/// <summary>
	/// Length of the seed used for deterministic key pair generation (32 bytes).
	/// </summary>
	public const int SeedLen = Native.CRYPTO_KX_SEEDBYTES;

	/// <summary>
	/// Length of derived session keys in bytes (32).
	/// </summary>
	public const int SessionKeyLen = Native.CRYPTO_KX_SESSIONKEYBYTES;

	/// <summary>
	/// Generates a new random key pair suitable for key exchange (crypto_kx).
	/// </summary>
	/// <param name="publicKey">Buffer to receive the generated public key. Must be exactly 32 bytes.</param>
	/// <param name="secretKey">Buffer to receive the generated secret key. Must be exactly 32 bytes.</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="publicKey"/> or <paramref name="secretKey"/> are not exactly 32 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if key pair generation fails internally.
	/// </exception>
	public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> secretKey)
	{
		if (publicKey.Length != PublicKeyLen)
			throw new ArgumentException($"Public key must be exactly {PublicKeyLen} bytes.", nameof(publicKey));
		if (secretKey.Length != SecretKeyLen)
			throw new ArgumentException($"Secret key must be exactly {SecretKeyLen} bytes.", nameof(secretKey));

		int rc = Native.crypto_kx_keypair(publicKey, secretKey);
		if (rc != 0)
			throw new LibSodiumException("Failed to generate random key pair.");
	}

	/// <summary>
	/// Deterministically generates a key pair from a provided seed.
	/// This method always produces the same key pair for the same seed.
	/// </summary>
	/// <param name="publicKey">Buffer to receive the derived public key. Must be exactly 32 bytes.</param>
	/// <param name="secretKey">Buffer to receive the derived secret key. Must be exactly 32 bytes.</param>
	/// <param name="seed">Seed used for deterministic generation. Must be exactly 32 bytes.</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="publicKey"/>, <paramref name="secretKey"/>, or <paramref name="seed"/> are not exactly 32 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if deterministic key pair generation fails internally.
	/// </exception>
	public static void GenerateKeyPairDeterministically(Span<byte> publicKey, Span<byte> secretKey, ReadOnlySpan<byte> seed)
	{
		if (publicKey.Length != PublicKeyLen)
			throw new ArgumentException($"Public key must be exactly {PublicKeyLen} bytes.", nameof(publicKey));
		if (secretKey.Length != SecretKeyLen)
			throw new ArgumentException($"Secret key must be exactly {SecretKeyLen} bytes.", nameof(secretKey));
		if (seed.Length != SeedLen)
			throw new ArgumentException($"Seed must be exactly {SeedLen} bytes.", nameof(seed));

		int rc = Native.crypto_kx_seed_keypair(publicKey, secretKey, seed);
		if (rc != 0)
			throw new LibSodiumException("Failed to generate deterministic key pair from seed.");
	}

	/// <summary>
	/// Derives client-side session keys for secure communication with a server.
	/// The generated keys allow secure and authenticated data exchange.
	/// </summary>
	/// <param name="rx">Buffer to receive the client's receiving key (used to decrypt data from server). Must be exactly 32 bytes.</param>
	/// <param name="tx">Buffer to receive the client's transmitting key (used to encrypt data sent to server). Must be exactly 32 bytes.</param>
	/// <param name="clientPk">Client's public key (32 bytes).</param>
	/// <param name="clientSk">Client's secret key (32 bytes).</param>
	/// <param name="serverPk">Server's public key (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if any provided buffer (<paramref name="rx"/>, <paramref name="tx"/>, <paramref name="clientPk"/>, <paramref name="clientSk"/>, <paramref name="serverPk"/>) is not exactly 32 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if client-side session key derivation fails internally.
	/// </exception>
	public static void DeriveClientSessionKeys(
		Span<byte> rx, Span<byte> tx,
		ReadOnlySpan<byte> clientPk, ReadOnlySpan<byte> clientSk,
		ReadOnlySpan<byte> serverPk)
	{
		if (rx.Length != SessionKeyLen)
			throw new ArgumentException($"RX key must be exactly {SessionKeyLen} bytes.", nameof(rx));
		if (tx.Length != SessionKeyLen)
			throw new ArgumentException($"TX key must be exactly {SessionKeyLen} bytes.", nameof(tx));

		int rc = Native.crypto_kx_client_session_keys(rx, tx, clientPk, clientSk, serverPk);
		if (rc != 0)
			throw new LibSodiumException("Failed to derive client session keys.");
	}

	/// <summary>
	/// Derives server-side session keys for secure communication with a client.
	/// The generated keys allow secure and authenticated data exchange.
	/// </summary>
	/// <param name="rx">Buffer to receive the server's receiving key (used to decrypt data from client). Must be exactly 32 bytes.</param>
	/// <param name="tx">Buffer to receive the server's transmitting key (used to encrypt data sent to client). Must be exactly 32 bytes.</param>
	/// <param name="serverPk">Server's public key (32 bytes).</param>
	/// <param name="serverSk">Server's secret key (32 bytes).</param>
	/// <param name="clientPk">Client's public key (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if any provided buffer (<paramref name="rx"/>, <paramref name="tx"/>, <paramref name="serverPk"/>, <paramref name="serverSk"/>, <paramref name="clientPk"/>) is not exactly 32 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if server-side session key derivation fails internally.
	/// </exception>
	public static void DeriveServerSessionKeys(
		Span<byte> rx, Span<byte> tx,
		ReadOnlySpan<byte> serverPk, ReadOnlySpan<byte> serverSk,
		ReadOnlySpan<byte> clientPk)
	{
		if (rx.Length != SessionKeyLen)
			throw new ArgumentException($"RX key must be exactly {SessionKeyLen} bytes.", nameof(rx));
		if (tx.Length != SessionKeyLen)
			throw new ArgumentException($"TX key must be exactly {SessionKeyLen} bytes.", nameof(tx));

		int rc = Native.crypto_kx_server_session_keys(rx, tx, serverPk, serverSk, clientPk);
		if (rc != 0)
			throw new LibSodiumException("Failed to derive server session keys.");
	}
}
