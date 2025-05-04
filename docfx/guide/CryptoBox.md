
# 🛡️ Public-Key Authenticated Encryption with CryptoBox

The `CryptoBox` API securely encrypts messages between two parties using public-key cryptography.  
The sender and the recipient each have a key pair, and the message is both encrypted and authenticated.  

Internally, it uses Curve25519 for key exchange, XSalsa20 for encryption, and Poly1305 for authentication.  
It supports both **combined** and **detached** modes, encryption using either a **keypair** or a **precomputed shared key**, and offers **automatic or manual nonce handling** — all through a unified, ergonomic API.

> 🧂Based on libsodium's [Authenticated encryption using `crypto_box`](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)<br/>
> ℹ️ *See also*: [API Reference for `CryptoBox`](../api/LibSodium.CryptoBox.yml)

---

## 🌟 Features

- Authenticated encryption with public-key cryptography.
- Curve25519 key exchange + XSalsa20-Poly1305 encryption.
- Combined and detached modes.
- Keypair or shared-key based encryption.
- Manual or automatic nonce handling.
- Unified API with optional parameters.
- Fully `Span<T>`-based, safe and efficient.

---

## 📏 Constants

| Name             | Value | Description                      |
|------------------|-------|----------------------------------|
| `PublicKeyLen`   | 32    | Length of a Curve25519 public key |
| `PrivateKeyLen`  | 32    | Length of a Curve25519 private key |
| `SharedKeyLen`   | 32    | Length of a precomputed shared key |
| `NonceLen`       | 24    | Length of the nonce               |
| `MacLen`         | 16    | Length of the authentication tag |
| `SeedLen`        | 32    | Length of a deterministic seed    |

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
CryptoBox.CalculateSharedKey(sharedKey, peerPublicKey, myPrivateKey);
```


---

## ✨ Encrypting and Decrypting Messages

The API provides two symmetric pairs:

- `EncryptWithKeypair(...)` uses the recipient's public key and sender's private key, while `DecryptWithKeypair(...)` uses the sender's public key and recipient's private key.
- `EncryptWithSharedKey(...)` / `DecryptWithSharedKey(...)` — use a precomputed shared key.

Each pair supports combined and detached modes, and optional manual nonce input.

### 📋 Combined Mode (Keypair, Auto Nonce)

```csharp
Span<byte> recipientPk = stackalloc byte[CryptoBox.PublicKeyLen];
Span<byte> recipientSk = stackalloc byte[CryptoBox.PrivateKeyLen];
CryptoBox.GenerateKeypair(recipientPk, recipientSk);

Span<byte> senderPk = stackalloc byte[CryptoBox.PublicKeyLen];
Span<byte> senderSk = stackalloc byte[CryptoBox.PrivateKeyLen];
CryptoBox.GenerateKeypair(senderPk, senderSk);

var message = Encoding.UTF8.GetBytes("Hello, world!");
Span<byte> ciphertext = stackalloc byte[message.Length + CryptoBox.MacLen + CryptoBox.NonceLen];

CryptoBox.EncryptWithKeypair(ciphertext, message, recipientPk, senderSk);

Span<byte> decrypted = stackalloc byte[message.Length];
CryptoBox.DecryptWithKeypair(decrypted, ciphertext, senderPk, recipientSk);
```

### 📋 Detached Mode (Keypair, Manual Nonce)

```csharp
Span<byte> nonce = stackalloc byte[CryptoBox.NonceLen];
Span<byte> mac = stackalloc byte[CryptoBox.MacLen];
Span<byte> ciphertext = stackalloc byte[message.Length];

CryptoBox.EncryptWithKeypair(ciphertext, message, recipientPk, senderSk, mac, nonce);
CryptoBox.DecryptWithKeypair(decrypted, ciphertext, senderPk, recipientPk, mac, nonce);
```

### 📋 Combined Mode (Shared Key, Auto Nonce)

```csharp
Span<byte> sharedKey = stackalloc byte[CryptoBox.SharedKeyLen];
// usually calculated with CalculateSharedKey()

Span<byte> ciphertext = stackalloc byte[message.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
CryptoBox.EncryptWithSharedKey(ciphertext, message, sharedKey);

CryptoBox.DecryptWithSharedKey(decrypted, ciphertext, sharedKey);
```

### 📋 Detached Mode (Shared Key, Manual Nonce)

```csharp
Span<byte> nonce = stackalloc byte[CryptoBox.NonceLen];
Span<byte> mac = stackalloc byte[CryptoBox.MacLen];
Span<byte> ciphertext = stackalloc byte[message.Length];

CryptoBox.EncryptWithSharedKey(ciphertext, message, sharedKey, mac, nonce);
CryptoBox.DecryptWithSharedKey(decrypted, ciphertext, sharedKey, mac, nonce);
```

--- 
## ⚠️ Error Handling

- `ArgumentException` — invalid input sizes.
- `LibSodiumException` — authentication failed or encryption/decryption error.

---

## 📝 Notes

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
