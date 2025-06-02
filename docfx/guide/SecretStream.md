# 🔒 Authenticated Stream Encryption with SecretStream

The `SecretStream` class in LibSodium.Net provides secure, authenticated stream-based encryption and decryption using the **XChaCha20-Poly1305** algorithm. It also supports additional authenticated data (AAD), allowing you to cryptographically bind headers or metadata to the encrypted stream. It's designed to handle large streams of data efficiently and securely.

> 🧂 Based on libsodium's [Encrypted streams and file encryption](https://doc.libsodium.org/secret-key_cryptography/secretstream)<br/>
> ℹ️ *See also*: [API Reference for `SecretStream`](../api/LibSodium.SecretStream.yml)

---

## ✨ Features

* Authenticated encryption ensures data integrity.
* Automatic chunking and handling of large data streams.
* Secure random key generation.
* Protection against nonce reuse.
* Accepts `SecureMemory<byte>` as key input.
* Supports additional authenticated data (AAD).

---

## 📋 Usage

LibSodium.Net accepts `Span<byte>`/`ReadOnlySpan<byte>`, `byte[]`, or `SecureMemory<byte>` as key inputs for synchronous methods.
For asynchronous methods, it accepts `Memory<byte>`/`ReadOnlyMemory<byte>`, `byte[]`, or `SecureMemory<byte>`.

Using `SecureMemory<byte>` is strongly recommended, as it protects key material in unmanaged memory with automatic zeroing and access control.

```csharp
byte[] key = new byte[CryptoSecretStream.KeyLen];
CryptoSecretStream.GenerateKey(key);
```

```csharp
using var key = new SecureMemory<byte>(CryptoSecretStream.KeyLen);
CryptoSecretStream.GenerateKey(key);
key.ProtectReadOnly();
```

Use `CryptoSecretStream.GenerateKey()` to generate a cryptographically secure random key. 
Alternatively, keys may be securely stored or derived using a key derivation function.

---

**Encrypting and decrypting files synchronously:**

```csharp
using var inputFile = File.OpenRead("plaintext.dat");
using var encryptedFile = File.Create("encrypted.dat");
using var decryptedFile = File.Create("decrypted.dat");

SecretStream.Encrypt(inputFile, encryptedFile, key);
encryptedFile.Position = 0;
SecretStream.Decrypt(encryptedFile, decryptedFile, key);
```


**Encrypting and decrypting files asynchronously:**

```csharp
using var inputFile = File.OpenRead("plaintext.dat");
using var encryptedFile = File.Create("encrypted.dat");
using var decryptedFile = File.Create("decrypted.dat");


await SecretStream.EncryptAsync(inputFile, encryptedFile, key);
encryptedFile.Position = 0;
await SecretStream.DecryptAsync(encryptedFile, decryptedFile, key);
```

**Encrypting and decrypting with AAD:**

To authenticate additional data (AAD), use the overloads that accept an `aad` parameter.
> ⚠️ The same AAD must be provided for both encryption and decryption to ensure verification.

```csharp
ReadOnlySpan<byte> aad = "header info"u8;
byte[] aadArray = aad.ToArray(); // Async methods require ReadOnlyMemory<byte>
```

```csharp
SecretStream.Encrypt(input, encrypted, key, aad);
SecretStream.Decrypt(encrypted, decrypted, key, aad);
```

```csharp
await SecretStream.EncryptAsync(input, encrypted, key, aadArray);
await SecretStream.DecryptAsync(encrypted, decrypted, key, aadArray);
```

---

## ⚠️ Security Considerations

* **Secure Key Management:** Protect your keys; losing them or exposing them compromises security. Use `SecureMemory<byte>` when possible.
* **Nonce Management:** Handled internally by `SecretStream`; avoid manual nonce reuse.
* **Integrity Checks:** Automatic using Poly1305 tags; any tampering results in exceptions.
* **AAD Integrity:** If you use AAD, it must match exactly on encryption and decryption, or the authentication will fail.

---

## ⚠️ Error Handling

Encryption and decryption throw specific exceptions for error conditions:

* `ArgumentException`: Invalid arguments (wrong key length, null streams).
* `LibSodiumException`: Authentication failed, typically from tampered data.

---

## 🕒 Performance Considerations

* `SecretStream` processes data in chunks (default: 64KB) for optimal balance between memory usage and performance.
* Utilize asynchronous methods (`EncryptAsync`/`DecryptAsync`) for IO-bound scenarios for better scalability.
