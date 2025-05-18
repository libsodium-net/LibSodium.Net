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
