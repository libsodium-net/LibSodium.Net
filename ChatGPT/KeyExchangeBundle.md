# 🔑 Key Exchange with CryptoKeyExchange

Securely establishing a shared secret between two parties is a foundational step for any encrypted communication channel. LibSodium.Net wraps libsodium’s **crypto\_kx** primitive in an ergonomic, allocation‑free API that is safe by default and AOT‑friendly.

> 🧂 Based on libsodium's [Key Exchange](https://doc.libsodium.org/key_exchange)**</br>
> ℹ️ See also: [API Reference for `CryptoKeyExchange`](../api/LibSodium.CryptoKeyExchange.yml)

---

## ✨ What Does Key Exchange Do?

Key exchange (sometimes called *authenticated key agreement*) lets two peers that each own a long‑term key pair derive **two fresh 32‑byte session keys** – one for sending (TX) and one for receiving (RX). These session keys can then be fed into other LibSodium.Net constructs such as **SecretBox** or **SecretStream** to encrypt traffic.

* **Confidential** – Only the two parties learn the session keys.
* **Integrity & Authenticity** – Each side proves possession of its secret key, preventing MitM attacks.
* **Speed** – Single round‑trip and constant‑time operations on Curve25519.

## 🌟 Features

* **Allocation‑free `Span<T>` API** – zero heap allocations.
* **Deterministic or random key generation** – choose reproducibility or fresh randomness.
* **Separate TX/RX keys** – enforces directionality and prevents nonce reuse.
* **AOT & Unity friendly** – works seamlessly in Ahead‑of‑Time compiled environments.
* **Defensive size checks** – throws early on invalid input lengths.

## ✨ Typical Scenarios

| Scenario                                | Why Key Exchange Fits                                                                          |
| --------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Client ↔️ Server TLS‑like handshake** | Derive symmetric keys before switching to an AEAD cipher for bulk data.                        |
| **IoT device onboarding**               | Small code size & no certificates required.                                                    |
| **P2P chat/file sharing**               | Each participant becomes *client* or *server* dynamically to agree on forward‑secure channels. |
| **Session re‑keying**                   | Periodically refresh symmetric keys without exchanging new public keys.                        |

> 📝 *The crypto\_kx API does **not** provide Perfect Forward Secrecy by itself; re‑run the exchange whenever you need new keys.*

## ✨ API Overview

### 📏 Constants

| Constant        | Size (bytes) | Purpose                      |
| --------------- | ------------ | ---------------------------- |
| `PublicKeyLen`  | 32           | Curve25519 public key.       |
| `SecretKeyLen`  | 32           | Private key.                 |
| `SeedLen`       | 32           | Deterministic key‑pair seed. |
| `SessionKeyLen` | 32           | TX or RX session key.        |

All constants are surfaced on **`CryptoKeyExchange`** for zero‑cost access.

### 📋 Core Methods

| Method                             | Role                                              |
| ---------------------------------- | ------------------------------------------------- |
| `GenerateKeyPair`                  | Random key pair.                                  |
| `GenerateKeyPairDeterministically` | Reproducible key pair from a 32‑byte seed.        |
| `DeriveClientSessionKeys`          | Client side of the handshake → produces (rx, tx). |
| `DeriveServerSessionKeys`          | Server side of the handshake → produces (rx, tx). |

> ℹ️ **Naming convention:** *Client TX = data you SEND*, *Client RX = data you RECEIVE*.

## 📋 Usage Example

```csharp
// Key generation (once)
Span<byte> clientPublicKey = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
Span<byte> clientSecretKey = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
CryptoKeyExchange.GenerateKeyPair(clientPublicKey, clientSecretKey);

Span<byte> serverPublicKey = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
Span<byte> serverSecretKey = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
CryptoKeyExchange.GenerateKeyPair(serverPublicKey, serverSecretKey);

// Derive session keys (per connection)
Span<byte> clientReceiveKey = stackalloc byte[CryptoKeyExchange.SessionKeyLen];
Span<byte> clientSendKey    = stackalloc byte[CryptoKeyExchange.SessionKeyLen];
CryptoKeyExchange.DeriveClientSessionKeys(clientReceiveKey, clientSendKey, clientPublicKey, clientSecretKey, serverPublicKey);

Span<byte> serverReceiveKey = stackalloc byte[CryptoKeyExchange.SessionKeyLen];
Span<byte> serverSendKey    = stackalloc byte[CryptoKeyExchange.SessionKeyLen];
CryptoKeyExchange.DeriveServerSessionKeys(serverReceiveKey, serverSendKey, serverPublicKey, serverSecretKey, clientPublicKey);

// Verify keys match
Debug.Assert(clientSendKey.SequenceEqual(serverReceiveKey)); // Upstream traffic
Debug.Assert(clientReceiveKey.SequenceEqual(serverSendKey)); // Downstream traffic

// Use with SecretBox
var ciphertext = SecretBox.Encrypt(message, nonce, clientSendKey);
var plaintext  = SecretBox.Decrypt(ciphertext, nonce, serverReceiveKey);
```

## ⚠️ Error Handling

* **Size checks** – All spans **must** match the declared constants. Otherwise `ArgumentException` or `ArgumentOutOfRangeException` is thrown.
* **Return codes** – Non‑zero return from native libsodium maps to `LibSodiumException`.
* **Dispose secrets carefully** – Zero out secret keys (`SecretKeyLen`) after use; consider `fixed` + `CryptographicOperations.ZeroMemory`.

## 📝 Security Notes

* Always transmit public keys over an authenticated channel or pin them out‑of‑band.
* Re‑key often if you require PFS. The operation is cheap.
* Combine with **SecretStream.Encrypt** / **Decrypt** (or their `Async` variants) for long‑lived encrypted pipes.
* Do **not** share the same session key across protocols; derive one per purpose using an HKDF if needed.

## 👀 See Also

* 🧂 [libsodium Key Exchange](https://doc.libsodium.org/key_exchange)
* ℹ️ [API Reference for `CryptoKeyExchange`](../api/LibSodium.CryptoKeyExchange.yml)

## KeyExchange native source code

```csharp
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
```

## KeyExchange API source code

```csharp
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
```

## KeyExchange tests source code

```csharp
namespace LibSodium.Tests;

public class CryptoKeyExchangeTests
{
	[Test]
	public void GenerateKeyPair_ShouldGenerateValidKeyPair()
	{
		Span<byte> publicKey = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> secretKey = stackalloc byte[CryptoKeyExchange.SecretKeyLen];

		CryptoKeyExchange.GenerateKeyPair(publicKey, secretKey);

		publicKey.ShouldNotBeZero();
		secretKey.ShouldNotBeZero();
		publicKey.ShouldNotBe(secretKey);
	}

	[Test]
	public void GenerateKeyPairDeterministically_ShouldProduceSameKeysFromSameSeed()
	{
		Span<byte> seed = stackalloc byte[CryptoKeyExchange.SeedLen];
		RandomGenerator.Fill(seed);

		Span<byte> publicKey1 = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> secretKey1 = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
		CryptoKeyExchange.GenerateKeyPairDeterministically(publicKey1, secretKey1, seed);

		Span<byte> publicKey2 = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> secretKey2 = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
		CryptoKeyExchange.GenerateKeyPairDeterministically(publicKey2, secretKey2, seed);

		publicKey1.ShouldBe(publicKey2);
		secretKey1.ShouldBe(secretKey2);
	}

	[Test]
	public void DeriveClientAndServerSessionKeys_ShouldDeriveMatchingSessionKeys()
	{
		Span<byte> clientPk = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> clientSk = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
		CryptoKeyExchange.GenerateKeyPair(clientPk, clientSk);

		Span<byte> serverPk = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> serverSk = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
		CryptoKeyExchange.GenerateKeyPair(serverPk, serverSk);

		Span<byte> clientRx = stackalloc byte[CryptoKeyExchange.SessionKeyLen];
		Span<byte> clientTx = stackalloc byte[CryptoKeyExchange.SessionKeyLen];

		CryptoKeyExchange.DeriveClientSessionKeys(clientRx, clientTx, clientPk, clientSk, serverPk);

		Span<byte> serverRx = stackalloc byte[CryptoKeyExchange.SessionKeyLen];
		Span<byte> serverTx = stackalloc byte[CryptoKeyExchange.SessionKeyLen];

		CryptoKeyExchange.DeriveServerSessionKeys(serverRx, serverTx, serverPk, serverSk, clientPk);

		clientTx.ShouldBe(serverRx, "Client's TX key should match Server's RX key.");
		clientRx.ShouldBe(serverTx, "Client's RX key should match Server's TX key.");
	}

	[Test]
	public void DeriveClientSessionKeys_WithInvalidLengths_ShouldThrowArgumentException()
	{
		var invalidBuffer = new byte[10];
		var validBuffer = new byte[CryptoKeyExchange.SessionKeyLen];
		var publicKey = new byte[CryptoKeyExchange.PublicKeyLen];
		var secretKey = new byte[CryptoKeyExchange.SecretKeyLen];

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.DeriveClientSessionKeys(invalidBuffer, validBuffer, publicKey, secretKey, publicKey));

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.DeriveClientSessionKeys(validBuffer, invalidBuffer, publicKey, secretKey, publicKey));
	}

	[Test]
	public void DeriveServerSessionKeys_WithInvalidLengths_ShouldThrowArgumentException()
	{
		var invalidBuffer = new byte[10];
		var validBuffer = new byte[CryptoKeyExchange.SessionKeyLen];
		var publicKey = new byte[CryptoKeyExchange.PublicKeyLen];
		var secretKey = new byte[CryptoKeyExchange.SecretKeyLen];

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.DeriveServerSessionKeys(invalidBuffer, validBuffer, publicKey, secretKey, publicKey));

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.DeriveServerSessionKeys(validBuffer, invalidBuffer, publicKey, secretKey, publicKey));
	}

	[Test]
	public void GenerateKeyPairDeterministically_WithInvalidSeedLength_ShouldThrowArgumentException()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> seed = stackalloc byte[CryptoKeyExchange.SeedLen - 1];
			Span<byte> publicKey = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
			Span<byte> secretKey = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
			CryptoKeyExchange.GenerateKeyPairDeterministically(publicKey, secretKey, seed);
		});
	}

	[Test]
	public void GenerateKeyPairDeterministically_WithInvalidKeyLengths_ShouldThrowArgumentException()
	{
		var seed = new byte[CryptoKeyExchange.SeedLen];
		var tooShortPk = new byte[CryptoKeyExchange.PublicKeyLen - 1];
		var tooShortSk = new byte[CryptoKeyExchange.SecretKeyLen - 1];

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.GenerateKeyPairDeterministically(tooShortPk, stackalloc byte[CryptoKeyExchange.SecretKeyLen], seed));

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.GenerateKeyPairDeterministically(stackalloc byte[CryptoKeyExchange.PublicKeyLen], tooShortSk, seed));
	}
}
```

