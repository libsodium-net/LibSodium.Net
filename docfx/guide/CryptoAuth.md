# 📜 CryptoAuth

The `CryptoAuth` API in **LibSodium.Net** provides secure message authentication using HMAC-SHA-512-256. This is useful for ensuring that a message was not altered and comes from a trusted sender who knows the secret key.

⚠️ **Warning:** `CryptoAuth` is deprecated use [`CryptoHmacSha512_256`](./MAC.md#-hmacsha512256) instead


> 🧂 Based on libsodium’s [Secret Key Authentication `crypto_auth`](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication) API  
> ℹ️ *See also*: [API Reference for `CryptoAuth`](../api/LibSodium.CryptoAuth.yml)

---

## 🌟 Features

- Message authentication using HMAC-SHA-512-256.
- Fixed-length secret keys and MACs.
- Strong tampering detection.
- Safe and efficient API using `Span<T>`.
- Fully interoperable with libsodium's `crypto_auth` functions.

---

## 🔍 What is Message Authentication?

Unlike encryption, **authentication** doesn't hide the contents of a message. It ensures that the message has **not been tampered with** and was created by someone who **knows the shared secret key**.

This is useful for protocols that need to validate integrity and authenticity but don't require confidentiality.

`CryptoAuth` uses:

- **HMAC-SHA-512-256**: a strong MAC algorithm with 32-byte output.
- A **32-byte key** shared between sender and receiver.

---

## ✨Usage Examples

### 📋 Key Generation

```csharp
Span<byte> key = stackalloc byte[CryptoAuth.KeyLen];
CryptoAuth.GenerateKey(key);
```

### 📋 MAC Generation

```csharp
Span<byte> mac = stackalloc byte[CryptoAuth.MacLen];
ReadOnlySpan<byte> message = Encoding.UTF8.GetBytes("Message to authenticate");

CryptoAuth.ComputeMac(mac, message, key);
```

### 📋 MAC Verification

```csharp
bool isValid = CryptoAuth.TryVerifyMac(mac, message, key);

if (isValid)
{
    Console.WriteLine("MAC is valid.");
}
else
{
    Console.WriteLine("MAC is invalid!");
}
```

### 📋 Strict Verification (throws on failure)

```csharp
CryptoAuth.VerifyMac(mac, message, key); // Throws LibSodiumException if verification fails
```

---

## ⚠️ Error Handling

- `ArgumentException` — input buffers are incorrect length.
- `LibSodiumException` — MAC computation or verification failed unexpectedly.

---

## 📝 Notes

- The MAC is **32 bytes** (`CryptoAuth.MacLen`).
- The secret key must be exactly **32 bytes** (`CryptoAuth.KeyLen`).
- This API does **not** encrypt your message, only authenticates it.
- Use `RandomGenerator.Fill()` or `CryptoAuth.GenerateKey()` to create secure keys.
- Never reuse keys across different algorithms or protocols.
