# 🔑 Public Key Cryptography

LibSodium.Net provides high-level APIs for public-key cryptography based on Curve25519 and Ed25519. This includes secure encryption between peers (`CryptoBox`), anonymous encryption (`Sealed Boxes`), and digital signatures (`CryptoSign`). LibSodium.Net also exposes the low-level scalar multiplication primitive via `CryptoScalarMult`, which implements X25519.

> 🧂 Based on [libsodium's Public-Key Cryptography](https://doc.libsodium.org/public-key_cryptography/)<br/>
> 🧂 Based on [libsodium's Point*scalar multiplication](https://doc.libsodium.org/advanced/scalar_multiplication)<br/>
> ℹ️ [API Reference: CryptoBox](../api/LibSodium.CryptoBox.yml)<br/>
> ℹ️ [API Reference: CryptoSign](../api/LibSodium.CryptoSign.yml)
> ℹ️ [API Reference: CryptoScalarMult](../api/LibSodium.CryptoScalarMult.yml)

---

## 🌟 Features

* Public-key authenticated encryption (`CryptoBox`)
* Anonymous encryption for messages (Sealed Boxes)
* Digital signatures with Ed25519 (`CryptoSign`)
* Span-based APIs for efficient, allocation-free usage
* Conversion from Ed25519 keys to Curve25519 (`CryptoSign.PublicKeyToCurve`, `CryptoSign.PrivateKeyToCurve`)

---

## ✨ CryptoBox — Authenticated Encryption

The `CryptoBox` API securely encrypts messages between two parties using public-key cryptography. The sender and the recipient each have a key pair, and the message is both encrypted and authenticated.

It also supports **Sealed Boxes** for anonymous encryption, allowing anyone to encrypt a message to a recipient without revealing their identity.

Internally, it uses Curve25519 for key exchange, XSalsa20 for encryption, and Poly1305 for authentication. It supports both **combined** and **detached** modes, encryption using either a **keypair** or a **precomputed shared key**, and offers **automatic or manual nonce handling** — all through a unified, ergonomic API.


> 🧂 Based on libsodium's [Authenticated encryption using `crypto_box`](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)<br/>
> 👀 [API Reference for `CryptoBox`](../api/LibSodium.CryptoBox.yml)

### 📏 Constants

| Name              | Value | Description                              |
| ----------------- | ----- | ---------------------------------------- |
| `PublicKeyLen`    | 32    | Curve25519 public key length             |
| `PrivateKeyLen`   | 32    | Curve25519 private key length            |
| `SharedKeyLen`    | 32    | Precomputed shared key length            |
| `NonceLen`        | 24    | Nonce length                             |
| `MacLen`          | 16    | Authentication tag length                |
| `SealOverheadLen` | 48    | Overhead added by `EncryptWithPublicKey` |

---

## 🗝️ Key Management

### 📋 Generate Keypair

```csharp
Span<byte> publicKey = stackalloc byte[CryptoBox.PublicKeyLen];
Span<byte> privateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
CryptoBox.GenerateKeypair(publicKey, privateKey);
```

### 📋 Deterministic Keypair from Seed

```csharp
Span<byte> seed = stackalloc byte[CryptoBox.SeedLen];
Span<byte> publicKey = stackalloc byte[CryptoBox.PublicKeyLen];
Span<byte> privateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
CryptoBox.GenerateKeypairDeterministically(publicKey, privateKey, seed);
```

### 📋 Precompute Shared Key

```csharp
Span<byte> sharedKey = stackalloc byte[CryptoBox.SharedKeyLen];
CryptoBox.CalculateSharedKey(sharedKey, otherPartyPublicKey, myPrivateKey);
```

### 📋 Convert Ed25519 to Curve25519

LibSodium.Net allows converting Ed25519 key pairs (used for digital signatures) to Curve25519 format, suitable for encryption and key exchange.

These converted keys can be used with the `CryptoBox` and `CryptoKeyExchange` APIs.


```csharp
Span<byte> edPk = stackalloc byte[CryptoSign.PublicKeyLen];
Span<byte> edSk = stackalloc byte[CryptoSign.PrivateKeyLen];
CryptoSign.GenerateKeyPair(edPk, edSk);

Span<byte> curvePk = stackalloc byte[CryptoBox.PublicKeyLen];
Span<byte> curveSk = stackalloc byte[CryptoBox.PrivateKeyLen];
CryptoSign.PublicKeyToCurve(curvePk, edPk);
CryptoSign.PrivateKeyToCurve(curveSk, edSk);
```

The resulting `curvePk` and `curveSk` can be used anywhere a Curve25519 key is expected.

---

## ✨ Encryption Modes

### 📋 Encrypt / Decrypt with Keypair (Combined, Auto Nonce)


```csharp
var message = Encoding.UTF8.GetBytes("Hello, world!");
Span<byte> ciphertext = stackalloc byte[message.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
CryptoBox.EncryptWithKeypair(ciphertext, message, recipientPublicKey, senderPrivateKey);

Span<byte> decrypted = stackalloc byte[message.Length];
CryptoBox.DecryptWithKeypair(decrypted, ciphertext, senderPublicKey, recipientPrivateKey);
AssertLite.True(decrypted.SequenceEqual(message));
```

### 📋 Encrypt / Decrypt with Keypair (Detached, Manual Nonce)


```csharp
Span<byte> nonce = stackalloc byte[CryptoBox.NonceLen];
Span<byte> mac = stackalloc byte[CryptoBox.MacLen];
Span<byte> ciphertext = stackalloc byte[message.Length];
CryptoBox.EncryptWithKeypair(ciphertext, message, recipientPublicKey, senderPrivateKey, mac, nonce);
CryptoBox.DecryptWithKeypair(decrypted, ciphertext, senderPublicKey, recipientPublicKey, mac, nonce);
```

### 📋 Encrypt / Decrypt with Shared Key (Combined, Auto Nonce)

```csharp
Span<byte> ciphertext = stackalloc byte[message.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
CryptoBox.EncryptWithSharedKey(ciphertext, message, sharedKey);
CryptoBox.DecryptWithSharedKey(decrypted, ciphertext, sharedKey);
AssertLite.True(decrypted.SequenceEqual(message));
```

### 📋 Encrypt / Decrypt with Shared Key (Detached, Manual Nonce)

```csharp
Span<byte> nonce = stackalloc byte[CryptoBox.NonceLen];
Span<byte> mac = stackalloc byte[CryptoBox.MacLen];
Span<byte> ciphertext = stackalloc byte[message.Length];
CryptoBox.EncryptWithSharedKey(ciphertext, message, sharedKey, mac, nonce);
CryptoBox.DecryptWithSharedKey(decrypted, ciphertext, sharedKey, mac, nonce);
```

### 📋 Sealed Boxes — Anonymous Encryption

Sealed boxes enable **anonymous encryption**: anyone can encrypt a message to a recipient’s public key without revealing their identity. Internally, a random ephemeral keypair is generated and embedded in the ciphertext.


```csharp
Span<byte> ciphertext = stackalloc byte[message.Length + CryptoBox.SealOverheadLen];
CryptoBox.EncryptWithPublicKey(ciphertext, message, recipientPublicKey);

Span<byte> decrypted = stackalloc byte[message.Length];
CryptoBox.DecryptWithPrivateKey(decrypted, ciphertext, recipientPrivateKey);
AssertLite.True(decrypted.SequenceEqual(message));
```

---

## ✨ CryptoSign — Digital Signatures

Uses Ed25519 to sign and verify messages. Produces 64-byte signatures. This is useful for verifying authenticity **without encryption**.

> 🧂 See: [libsodium crypto\_sign](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)<br/>
> 👀 [API Reference for `CryptoSign`](../api/LibSodium.CryptoSign.yml)

### 📏 Constants

| Name            | Value | Description                       |
| --------------- | ----- | --------------------------------- |
| `PublicKeyLen`  | 32    | Ed25519 public key length         |
| `PrivateKeyLen` | 64    | Ed25519 private key length        |
| `SignatureLen`  | 64    | Signature length                  |
| `SeedLen`       | 32    | Seed length for deterministic key |

### 📋 Generate Keypair

```csharp
Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeyLen];
Span<byte> privateKey = stackalloc byte[CryptoSign.PrivateKeyLen];
CryptoSign.GenerateKeyPair(publicKey, privateKey);
```

### 📋 Sign and Verify

```csharp
Span<byte> signature = stackalloc byte[CryptoSign.SignatureLen];
CryptoSign.Sign(message, signature, privateKey);

bool ok = CryptoSign.TryVerify(message, signature, publicKey);
CryptoSign.Verify(message, signature, publicKey); // throws LibSodiumException if the signature is invalid
```

---
## ✨ CryptoScalarMult — Raw Scalar Multiplication

The `CryptoScalarMult` API exposes the low-level scalar multiplication primitive `crypto_scalarmult`, based on Curve25519.
This operation implements the **X25519** algorithm (ECDH over Curve25519), as defined in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).
It forms the foundation of key exchange protocols such as `CryptoBox`, `CryptoKeyExchange`, and others.

This API is rarely needed directly. Prefer CryptoBox or CryptoKeyExchange unless you need protocol-level control or are replicating RFC 7748 behavior manually.

> 🧂 Based on libsodium's [Scalar multiplication](https://doc.libsodium.org/advanced/scalar_multiplication)<br/>
> ℹ️ [API Reference for `CryptoScalarMult`](../api/LibSodium.CryptoScalarMult.yml)

---

### 📏 Constants

| Name            | Value | Description                       |
| --------------- | ----- | --------------------------------- |
| `PublicKeyLen`  | 32    | Length of the public key (q = nB) |
| `PrivateKeyLen` | 32    | Length of the private scalar      |
| `SharedKeyLen`  | 32    | Length of the computed q = nP     |

---

### 📋 Calculate Public Key

Computes the public key `q = n·B` given a private scalar `n`:

```csharp
Span<byte> privateKey = stackalloc byte[CryptoScalarMult.PrivateKeyLen];
Span<byte> publicKey = stackalloc byte[CryptoScalarMult.PublicKeyLen];
RandomGenerator.Fill(privateKey);
CryptoScalarMult.CalculatePublicKey(publicKey, privateKey);
```

---

### 📋 Compute Shared Point

Performs scalar multiplication `q = n·P` with a private scalar and a peer’s public key:

```csharp
Span<byte> sharedPoint = stackalloc byte[CryptoScalarMult.SharedKeyLen];
CryptoScalarMult.Compute(sharedPoint, myPrivateKey, peerPublicKey);
```

---

### ⚠️ Avoid Using `q` Directly as a Shared Key

Many `(privateKey, publicKey)` pairs can produce the **same result `q`** when using `CryptoScalarMult`.
This is because `q` is a point on the curve, and scalar multiplication is not injective.

A safer and recommended approach is to derive a shared key using a cryptographic hash of the transcript:

```
sharedKey = H(q || pk1 || pk2)
```

This binds the result to the specific public keys involved, preventing ambiguity or replay.
The order of the public keys must be agreed upon (e.g., lexicographically or based on fixed roles) to ensure both sides derive the same key.

---

### 📋 Recommended Derivation Pattern

```csharp
using System.Diagnostics;

Span<byte> clientPrivateKey = stackalloc byte[CryptoScalarMult.PrivateKeyLen];
Span<byte> clientPublicKey  = stackalloc byte[CryptoScalarMult.PublicKeyLen];
Span<byte> serverPrivateKey = stackalloc byte[CryptoScalarMult.PrivateKeyLen];
Span<byte> serverPublicKey  = stackalloc byte[CryptoScalarMult.PublicKeyLen];

Span<byte> sharedPointClient = stackalloc byte[CryptoScalarMult.SharedKeyLen];
Span<byte> sharedPointServer = stackalloc byte[CryptoScalarMult.SharedKeyLen];

Span<byte> derivedKeyClient = stackalloc byte[CryptoGenericHash.HashLen];
Span<byte> derivedKeyServer = stackalloc byte[CryptoGenericHash.HashLen];

// Generate key pairs
RandomGenerator.Fill(clientPrivateKey);
RandomGenerator.Fill(serverPrivateKey);
CryptoScalarMult.CalculatePublicKey(clientPublicKey, clientPrivateKey);
CryptoScalarMult.CalculatePublicKey(serverPublicKey, serverPrivateKey);

// Derive shared key on the client side
CryptoScalarMult.Compute(sharedPointClient, clientPrivateKey, serverPublicKey);
using (var hash = CryptoGenericHash.CreateIncrementalHash())
{
    hash.Update(sharedPointClient);
    hash.Update(clientPublicKey);
    hash.Update(serverPublicKey);
    hash.Final(derivedKeyClient);
}

// Derive shared key on the server side
CryptoScalarMult.Compute(sharedPointServer, serverPrivateKey, clientPublicKey);
using (var hash = CryptoGenericHash.CreateIncrementalHash())
{
    hash.Update(sharedPointServer);
    hash.Update(clientPublicKey);
    hash.Update(serverPublicKey);
    hash.Final(derivedKeyServer);
}

// Validate both parties derived the same key
Debug.Assert(derivedKeyClient.SequenceEqual(derivedKeyServer));
```

---
## ⚠️ Error Handling

- `ArgumentException` — when input buffers have incorrect lengths or invalid parameters.
- `LibSodiumException` — when authentication fails or a crypto operation cannot complete.

## 📝 Notes

* Sealed boxes are anonymous: the recipient cannot identify the sender.
* `CryptoBox` uses `crypto_box_easy` internally; `CryptoSign` uses `crypto_sign_detached`.
* All APIs are Span-friendly and do not allocate memory internally.
* `EncryptWithPublicKey` prepends a 32-byte ephemeral public key and 16-byte MAC.
* Use `CryptoSign` when authentication is required **without** encryption.
* `CryptoScalarMult` is a low-level primitive and does not provide authentication.
* Avoid using scalar multiplication output directly as a key — always apply a hash.

---

## 👀 See Also

* [API Reference: CryptoBox](../api/LibSodium.CryptoBox.yml)
* [API Reference: CryptoSign](../api/LibSodium.CryptoSign.yml)
* [API Reference: CryptoScalarMult](../api/LibSodium.CryptoScalarMult.yml)
* [libsodium.org Public-Key Crypto](https://doc.libsodium.org/public-key_cryptography/)
* [libsodium scalar multiplication](https://doc.libsodium.org/advanced/scalar_multiplication)
* [RFC 7748 – X25519](https://datatracker.ietf.org/doc/html/rfc7748)

