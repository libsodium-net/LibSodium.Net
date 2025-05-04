# 🔒 Authenticated Stream Encryption with SecretStream

The `SecretStream` class in **LibSodium.Net** provides secure, authenticated stream-based encryption and decryption using the **XChaCha20-Poly1305** algorithm. It's designed to handle large streams of data efficiently and securely.

>🧂 Based on libsodium's [Encrypted streams and file encryption](https://doc.libsodium.org/secret-key_cryptography/secretstream)<br/>
> ℹ️ *See also*: [API Reference for `SecretStream`](../api/LibSodium.SecretStream.yml)

---

## ✨ Key Features

- Authenticated encryption ensures data integrity.
- Automatic chunking and handling of large data streams.
- Secure random key generation.
- Protection against nonce reuse.

---

## ✨ Basic Usage

### 📋 Generating a Secret Key

A secret key must be securely generated and managed:

```csharp
byte[] key = new byte[CryptoSecretStream.KeyLen];
CryptoSecretStream.GenerateKey(key);
```

### 📋 Encrypting Data

Encrypting data streams asynchronously:

```csharp
using var inputFile = File.OpenRead("plaintext.dat");
using var encryptedFile = File.Create("encrypted.dat");

await SecretStream.EncryptAsync(inputFile, encryptedFile, key);
```

Synchronous Encryption:

```csharp
using var inputFile = File.OpenRead("plaintext.dat");
using var encryptedFile = File.Create("encrypted.dat");

SecretStream.Encrypt(inputFile, encryptedFile, key);
```

### 📋 Decrypting Data

Decrypting asynchronously the encrypted data back to plaintext:

```csharp
using var encryptedFile = File.OpenRead("encrypted.dat");
using var decryptedFile = File.Create("decrypted.dat");

await SecretStream.DecryptAsync(encryptedFile, decryptedFile, key);
```

Synchronous Decryption:

```csharp
using var encryptedFile = File.OpenRead("encrypted.dat");
using var decryptedFile = File.Create("decrypted.dat");

SecretStream.Decrypt(encryptedFile, decryptedFile, key);
```

---

## ⚠️ Security Considerations

- **Secure Key Management:** Protect your keys; losing them or exposing them compromises security.
- **Nonce Management:** Handled internally by `SecretStream`; avoid manual nonce reuse.
- **Integrity Checks:** Automatic using Poly1305 tags; any tampering results in exceptions.

---

## ⚠️ Error Handling

Encryption and decryption throw specific exceptions for error conditions:

- `ArgumentException`: Invalid arguments (wrong key length, null streams).
- `LibSodiumException`: Authentication failed, typically from tampered data.

---

## 🕒 Performance Considerations

- `SecretStream` processes data in chunks (default: 64KB) for optimal balance between memory usage and performance.
- Utilize asynchronous methods (`EncryptAsync`/`DecryptAsync`) for IO-bound scenarios for better scalability.

