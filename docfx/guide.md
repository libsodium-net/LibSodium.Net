# 🔐 Introduction to LibSodium.Net

[**LibSodium.Net**](https://github.com/LibSodium-Net/LibSodium.Net) provides .NET developers with easy-to-use bindings for [libsodium](https://doc.libsodium.org/), a powerful, modern cryptography library widely recognized for its simplicity and security. This makes it straightforward to add robust cryptographic functionality to your .NET applications.

## ✨ Why LibSodium.Net?

- **Cross-platform**: Seamless support across Windows, Linux, and macOS.
- **Modern Cryptography**: Includes authenticated encryption, public-key cryptography, hashing, key derivation, and digital signatures.
- **Simple and Secure API**: Designed to reduce complexity, helping you implement cryptography correctly and securely.
- **Secure Memory Handling**: Sensitive data management to minimize risks like memory leaks or data exposure.
- **Span<T> over Arrays**: Optimized for performance and memory efficiency by using `Span<T>` instead of heap-allocated arrays.
- **AOT Compatible**: Uses `LibraryImport` (source-generated P/Invoke) instead of `DllImport`, making it fully compatible with AOT compilation environments.


---

# 🚀 Getting Started with LibSodium.Net

Here's how you can quickly integrate LibSodium.Net into your .NET projects.

## 📦 Install via NuGet

You can easily install LibSodium.Net using the NuGet package manager:

### CLI

Using the .NET CLI:

```bash
dotnet add package LibSodium.Net
```

### Visual Studio

1. Right-click your project in Solution Explorer.
2. Choose **Manage NuGet Packages**.
3. Search for `LibSodium.Net` and click **Install**.

### Package Manager Console

```powershell
Install-Package LibSodium.Net
```

# 🧱 SecretBox

The `SecretBox` API in **LibSodium.Net** provides a simple and secure way to perform symmetric authenticated encryption using the XSalsa20 stream cipher and Poly1305 MAC. It supports both combined and detached encryption modes.

---

## 🔐 SecretBox Features

- **Symmetric authenticated encryption** using XSalsa20-Poly1305
- **Support for combined and detached modes**
- **Automatic or manual nonce handling**
- **Tamper-proof via MAC verification**

---

## 🔒 Encrypting and Decrypting Messages

### ✅ Combined Mode (Manual Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
Span<byte> nonce = stackalloc byte[SecretBox.NonceLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(nonce);

var plaintext = Encoding.UTF8.GetBytes("Hello, secure world!");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + SecretBox.MacLen];

// Encrypt
var result = SecretBox.EncryptCombined(ciphertext, plaintext, key, nonce);

// Decrypt
Span<byte> decrypted = stackalloc byte[plaintext.Length];
var recovered = SecretBox.DecryptCombined(decrypted, result, key, nonce);

Console.WriteLine(Encoding.UTF8.GetString(recovered));
```

### ✅ Combined Mode (Auto Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
RandomGenerator.Fill(key);

var plaintext = Encoding.UTF8.GetBytes("Auto-nonce mode test");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + SecretBox.MacLen + SecretBox.NonceLen];

var encrypted = SecretBox.EncryptCombined(ciphertext, plaintext, key);
Span<byte> decrypted = stackalloc byte[plaintext.Length];

var recovered = SecretBox.DecryptCombined(decrypted, encrypted, key);
Console.WriteLine(Encoding.UTF8.GetString(recovered));
```

---

### 🧩 Detached Mode (Manual Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
Span<byte> nonce = stackalloc byte[SecretBox.NonceLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(nonce);

var plaintext = Encoding.UTF8.GetBytes("Detached mode message");
Span<byte> ciphertext = stackalloc byte[plaintext.Length];
Span<byte> mac = stackalloc byte[SecretBox.MacLen];

SecretBox.EncryptDetached(ciphertext, mac, plaintext, key, nonce);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
var output = SecretBox.DecryptDetached(decrypted, ciphertext, key, mac, nonce);

Console.WriteLine(Encoding.UTF8.GetString(output));
```

### 🧩 Detached Mode (Auto Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
RandomGenerator.Fill(key);

var plaintext = Encoding.UTF8.GetBytes("Auto-nonce detached mode");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + SecretBox.NonceLen];
Span<byte> mac = stackalloc byte[SecretBox.MacLen];

SecretBox.EncryptDetached(ciphertext, mac, plaintext, key);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
var output = SecretBox.DecryptDetached(decrypted, ciphertext, key, mac);

Console.WriteLine(Encoding.UTF8.GetString(output));
```

---

## ⚠️ Error Handling

SecretBox methods throw:

- `ArgumentException` — if inputs are the wrong size.
- `LibSodiumException` — if decryption fails due to tampering or incorrect keys.

---

## 📌 Notes

- Always use a **new random nonce** for each encryption.
- Decryption verifies the MAC before returning plaintext.
- Use `RandomGenerator.Fill()` to securely fill nonces and keys.

---

# SecretStream

The `SecretStream` class in **LibSodium.Net** provides secure, authenticated stream-based encryption and decryption using the **XChaCha20-Poly1305** algorithm. It's designed to handle large streams of data efficiently and securely.

## Key Features
- Authenticated encryption ensures data integrity.
- Automatic chunking and handling of large data streams.
- Secure random key generation.
- Protection against nonce reuse.

## Basic Usage

### 1. Generating a Secret Key

A secret key must be securely generated and managed:

```csharp
byte[] key = new byte[CryptoSecretStream.KeyLen];
CryptoSecretStream.GenerateKey(key);
```

### 2. Encrypting Data

Encrypting data streams:

```csharp
using var inputFile = File.OpenRead("plaintext.dat");
using var encryptedFile = File.Create("encrypted.dat");

await SecretStream.EncryptAsync(inputFile, encryptedFile, key);
```

#### Synchronous Encryption:

```csharp
using var inputFile = File.OpenRead("plaintext.dat");
using var encryptedFile = File.Create("encrypted.dat");

SecretStream.Encrypt(inputFile, encryptedFile, key);
```

### 3. Decrypting Data

Decrypting the encrypted data back to plaintext:

```csharp
using var encryptedFile = File.OpenRead("encrypted.dat");
using var decryptedFile = File.Create("decrypted.dat");

await SecretStream.DecryptAsync(encryptedFile, decryptedFile, key);
```

#### Synchronous Decryption:

```csharp
using var encryptedFile = File.OpenRead("encrypted.dat");
using var decryptedFile = File.Create("decrypted.dat");

SecretStream.Decrypt(encryptedFile, decryptedFile, key);
```

## Security Considerations
- **Secure Key Management:** Protect your keys; losing them or exposing them compromises security.
- **Nonce Management:** Handled internally by `SecretStream`; avoid manual nonce reuse.
- **Integrity Checks:** Automatic using Poly1305 tags; any tampering results in exceptions.

## Error Handling

Encryption and decryption throw specific exceptions for error conditions:

- `ArgumentException`: Invalid arguments (wrong key length, null streams).
- `LibSodiumException`: Authentication failed, typically from tampered data.

## Performance Considerations
- `SecretStream` processes data in chunks (default: 64KB) for optimal balance between memory usage and performance.
- Utilize asynchronous methods (`EncryptAsync`/`DecryptAsync`) for IO-bound scenarios for better scalability.


## 🛡️ SecureMemory

When working with cryptographic data, it's essential to ensure that sensitive information doesn't get leaked through memory dumps, swapping, or garbage collection. LibSodium.Net provides `SecureMemory` and `SecureMemory<T>` as robust tools to manage sensitive data safely in unmanaged memory.

These APIs leverage libsodium's `sodium_malloc`, `sodium_mlock`, and related memory protection functions to offer secure, optionally read-only memory regions that are wiped on disposal.

---

### 🧩 SecureMemory&lt;T&gt;

`SecureMemory<T>` is a managed wrapper around unmanaged memory that stores a span of unmanaged type `T`. It ensures:

- Memory is allocated using `sodium_allocarray`.
- Memory is wiped with `sodium_memzero` on disposal.
- Optional read-only protection using `ProtectReadOnly()`.
- Optional read-write toggle with `ProtectReadWrite()`.
- Safe access through `Span<T>`, `Memory<T>`, `ReadOnlySpan<T>`, and `ReadOnlyMemory<T>`.

#### ✅ Basic Usage

```csharp
using var secure = SecureMemory.Create<byte>(32); // Allocate secure memory
var span = secure.AsSpan(); // Write access

RandomGenerator.Fill(span); // Fill with sensitive data

secure.ProtectReadOnly(); // Make it read-only
var readOnly = secure.AsReadOnlySpan(); // Safe read-only view

secure.ProtectReadWrite(); // Allow writing again
```

#### 🔒 Safety Features

- Accessing a `SecureMemory<T>` object after disposal throws `ObjectDisposedException`.
- Accessing writable span when read-only throws `InvalidOperationException`.
- Any span or memory obtained prior to disposal becomes invalid. Using it after the object is disposed may result in `AccessViolationException`.
- Writing through a span obtained before marking the memory as read-only will throw an `AccessViolationException`.
- Memory is finalized and securely freed if not explicitly disposed.

---

### 🔧 SecureMemory Utilities

`SecureMemory` also provides utility methods for working with unmanaged memory spans directly:

#### 🔐 Allocate Secure Buffers

```csharp
var span = SecureMemory.Allocate<byte>(64);
// Use span...
SecureMemory.Free(span); // Free when done
```

> All allocations are initialized with `0xDB` for predictable testing.

#### 🔐 Zeroing Buffers

```csharp
byte[] buffer = { 1, 2, 3 };
SecureMemory.MemZero(buffer); // Zeros array securely
```

#### 🔐 Lock/Unlock Memory

```csharp
var span = SecureMemory.Allocate<byte>(128);
SecureMemory.MemLock(span); // Prevents swapping to disk
SecureMemory.MemUnlock(span);
SecureMemory.Free(span);
```

#### 🔐 Read-Only & Read-Write Protections

```csharp
var span = SecureMemory.Allocate<long>(4);
var readOnlySpan = SecureMemory.ProtectReadOnly(span);
var writableSpan = SecureMemory.ProtectReadWrite(readOnlySpan);
```

---

### ⚠️ Security Considerations

- Do **not** pass managed memory (e.g., `new byte[1024]`) to `Free()`. Doing so can corrupt memory.
- Secure memory functions work only with unmanaged memory allocated by `SecureMemory.Allocate()`.
- Avoid using spans or memory references after the backing `SecureMemory<T>` has been disposed; doing so can cause undefined behavior or `AccessViolationException`.
- Writing to memory through a previously obtained span after calling `ProtectReadOnly()` will throw an `AccessViolationException`.
- Always dispose `SecureMemory<T>` when done, or use `using` to ensure cleanup.

---

### ✅ Unit-Tested Reliability

The implementation is backed by comprehensive tests ensuring:

- Memory is initialized to `0xDB` for testing predictability
- Read-only enforcement and write protection
- Exception safety on misuse
- Proper finalization and disposal semantics

---

SecureMemory APIs are essential for handling secrets like keys, passwords, or tokens securely. They give you granular control over how and when memory is allocated, accessed, and cleared—adding another layer of defense in your cryptographic applications.



