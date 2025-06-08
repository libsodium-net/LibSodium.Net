
# 🛡️ Public-Key Authenticated Encryption with CryptoBox

The `CryptoBox` API securely encrypts messages between two parties using public-key cryptography. The sender and the recipient each have a key pair, and the message is both encrypted and authenticated.

It also supports **Sealed Boxes** for anonymous encryption, allowing anyone to encrypt a message to a recipient without revealing their identity.

Internally, it uses Curve25519 for key exchange, XSalsa20 for encryption, and Poly1305 for authentication. It supports both **combined** and **detached** modes, encryption using either a **keypair** or a **precomputed shared key**, and offers **automatic or manual nonce handling** — all through a unified, ergonomic API.

> 🧂Based on libsodium's [Authenticated encryption using `crypto_box`](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)<br/>
> ℹ️ *See also*: [API Reference for `CryptoBox`](../api/LibSodium.CryptoBox.yml)

---

## 🌟 Features

- Authenticated encryption with public-key cryptography.
- anonymous encryption (`Sealed Boxes`).
- Curve25519 key exchange + XSalsa20-Poly1305 encryption.
- Combined and detached modes.
- Keypair or shared-key based encryption.
- Manual or automatic nonce handling.
- Unified API with optional parameters.
- Fully `Span<T>`-based, safe and efficient.
- Keys and seeds can be provided as `SecureMemory<byte>`, `Span<byte>`/`ReadOnlySpan<byte>`, and `byte[]`.

---

## 📏 Constants

| Name              | Value | Description                              |
| ----------------- | ----- | ---------------------------------------- |
| `PublicKeyLen`    | 32    | Curve25519 public key length             |
| `PrivateKeyLen`   | 32    | Curve25519 private key length            |
| `SharedKeyLen`    | 32    | Precomputed shared key length            |
| `NonceLen`        | 24    | Nonce length                             |
| `MacLen`          | 16    | Authentication tag length                |
| `SealOverheadLen` | 48    | Overhead added by `EncryptWithPublicKey` |

---

## 📋 CryptoBox Key Management

**Generate random key pair:**

```csharp
// SecureMemory
Span<byte> publicKey = stackalloc byte[CryptoBox.PublicKeyLen];
using var privateKey = new SecureMemory<byte>(CryptoBox.PrivateKeyLen);
CryptoBox.GenerateKeypair(publicKey, privateKey);
privateKey.ProtectReadOnly();
```

```csharp
// Span
Span<byte> publicKey = stackalloc byte[CryptoBox.PublicKeyLen];
Span<byte> privateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
CryptoBox.GenerateKeypair(publicKey, privateKey);
```

**Deterministic key pair from seed:**

```csharp
// SecureMemory
using var seed = new SecureMemory<byte>(CryptoBox.SeedLen);
//TODO: fill the seed using seed.AsSpan() 
seed.ProtectReadOnly();
Span<byte> publicKey = stackalloc byte[CryptoBox.PublicKeyLen];
using var privateKey = new SecureMemory<byte>(CryptoBox.PrivateKeyLen);
CryptoBox.GenerateKeypairDeterministically(publicKey, privateKey, seed);
privateKey.ProtectReadOnly();
```


```csharp
// Span
Span<byte> seed = stackalloc byte[CryptoBox.SeedLen];
//TODO: fill the seed
Span<byte> publicKey = stackalloc byte[CryptoBox.PublicKeyLen];
Span<byte> privateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
CryptoBox.GenerateKeypairDeterministically(publicKey, privateKey, seed);
```

**Precompute shared key:**

```csharp
// SecureMemory
using var  sharedKey = SecureMemory<byte>(CryptoBox.SharedKeyLen);
CryptoBox.CalculateSharedKey(sharedKey, otherPartyPublicKey, myPrivateKey);
sharedKey.ProtectReadOnly();
```

```csharp
// Span
Span<byte> sharedKey = stackalloc byte[CryptoBox.SharedKeyLen];
CryptoBox.CalculateSharedKey(sharedKey, otherPartyPublicKey, myPrivateKey);
```

---

## ✨ Encrypting and Decrypting with CryptoBox

**Encrypt / Decrypt with Keypair (Combined, Auto Nonce):**


```csharp
var message = Encoding.UTF8.GetBytes("Hello, world!");
Span<byte> ciphertext = stackalloc byte[message.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
CryptoBox.EncryptWithKeypair(ciphertext, message, recipientPublicKey, senderPrivateKey);

Span<byte> decrypted = stackalloc byte[message.Length];
CryptoBox.DecryptWithKeypair(decrypted, ciphertext, senderPublicKey, recipientPrivateKey);
AssertLite.True(decrypted.SequenceEqual(message));
```

**Encrypt / Decrypt with Keypair (Detached, Manual Nonce)**


```csharp
Span<byte> nonce = stackalloc byte[CryptoBox.NonceLen];
Span<byte> mac = stackalloc byte[CryptoBox.MacLen];
Span<byte> ciphertext = stackalloc byte[message.Length];
CryptoBox.EncryptWithKeypair(ciphertext, message, recipientPublicKey, senderPrivateKey, mac, nonce);
CryptoBox.DecryptWithKeypair(decrypted, ciphertext, senderPublicKey, recipientPublicKey, mac, nonce);
```

**Encrypt / Decrypt with Shared Key (Combined, Auto Nonce):**

```csharp
Span<byte> ciphertext = stackalloc byte[message.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
CryptoBox.EncryptWithSharedKey(ciphertext, message, sharedKey);
CryptoBox.DecryptWithSharedKey(decrypted, ciphertext, sharedKey);
Debug.Assert(decrypted.SequenceEqual(message));
```

**Encrypt / Decrypt with Shared Key (Detached, Manual Nonce):**

```csharp
Span<byte> nonce = stackalloc byte[CryptoBox.NonceLen];
Span<byte> mac = stackalloc byte[CryptoBox.MacLen];
Span<byte> ciphertext = stackalloc byte[message.Length];
CryptoBox.EncryptWithSharedKey(ciphertext, message, sharedKey, mac, nonce);
CryptoBox.DecryptWithSharedKey(decrypted, ciphertext, sharedKey, mac, nonce);
```

**Sealed Boxes — Anonymous Encryption:**

Sealed boxes enable **anonymous encryption**: anyone can encrypt a message to a recipient’s public key without revealing their identity.

```csharp
Span<byte> ciphertext = stackalloc byte[message.Length + CryptoBox.SealOverheadLen];
CryptoBox.EncryptWithPublicKey(ciphertext, message, recipientPublicKey);

Span<byte> decrypted = stackalloc byte[message.Length];
CryptoBox.DecryptWithPrivateKey(decrypted, ciphertext, recipientPrivateKey);
Debug.Assert(decrypted.SequenceEqual(message));
```

--- 
## ⚠️ Error Handling

- `ArgumentException` — invalid input sizes.
- `LibSodiumException` — authentication failed or encryption/decryption error.

---

## 📝 Notes

> ⚠️ `CryptoBox` derives the shared key from `Q = scalarmult(s, P)` using `HSalsa20(Q, 0)`.  
Since many `(s, P)` pairs can produce the same `Q`, the derived key will also be the same,  
because the ambiguity is not eliminated by HSalsa20. Therefore, using `CryptoBox` for new development is **not recommended**.

- In combined mode, the MAC is **prepended** to the ciphertext.
- In detached mode, the MAC is returned separately.
- If you omit the `nonce`, a secure random one is generated and prepended to the ciphertext.
- Use `EncryptWithKeypair` / `DecryptWithKeypair` for sender-recipient encryption.
- Use `EncryptWithSharedKey` / `DecryptWithSharedKey` when a shared key has been derived beforehand.
- Always check decrypted data — authentication failure throws.




---

## 👀 See Also

- [libsodium crypto_box documentation](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)
- [API Reference](../api/LibSodium.CryptoBox.yml)
