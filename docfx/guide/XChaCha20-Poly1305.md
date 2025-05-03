# 🔐 XChaCha20-Poly1305

The `XChaCha20Poly1305` API in **LibSodium.Net** provides authenticated encryption with associated data (AEAD) and extended nonce support (192-bit), making it safer for use in systems where nonce reuse is a concern. It supports both **combined** and **detached** encryption modes, and allows **manual** or **automatic** nonce handling through a unified API.

> 🧂 Based on libsodium's [XChaCha20-Poly1305 construction](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)<br/>
> ℹ️ *See also*: [API Reference for `XChaCha20Poly1305`](../api/LibSodium.XChaCha20Poly1305.yml)

---

## 🌟 Features

- Authenticated encryption with associated data (AEAD).
- 24-byte nonce (192-bit) minimizes risk of nonce reuse.
- Combined and detached mode support through a single API.
- Optional `additionalData` for protocol-level authentication.
- Manual or automatic nonce handling.
- `Span<T>`-based API for high performance and low allocations.

---

## ✨ Encrypting and Decrypting Messages

Use the `Encrypt` and `Decrypt` methods to perform authenticated encryption. The mode is determined by the presence of the optional `mac` parameter.

### 📋 Combined Mode (Auto Nonce, No AAD)

```csharp
Span<byte> key = stackalloc byte[XChaCha20Poly1305.KeyLen];
RandomGenerator.Fill(key);

var plaintext = Encoding.UTF8.GetBytes("Auto nonce test");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + XChaCha20Poly1305.MacLen + XChaCha20Poly1305.NonceLen];

XChaCha20Poly1305.Encrypt(ciphertext, plaintext, key);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
XChaCha20Poly1305.Decrypt(decrypted, ciphertext, key);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

### 📋 Combined Mode (Manual Nonce with AAD)

```csharp
Span<byte> key = stackalloc byte[XChaCha20Poly1305.KeyLen];
Span<byte> nonce = stackalloc byte[XChaCha20Poly1305.NonceLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(nonce);

var plaintext = Encoding.UTF8.GetBytes("With AAD and nonce");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + XChaCha20Poly1305.MacLen];
Span<byte> aad = Encoding.UTF8.GetBytes("metadata");

XChaCha20Poly1305.Encrypt(ciphertext, plaintext, key, aad: aad, nonce: nonce);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
XChaCha20Poly1305.Decrypt(decrypted, ciphertext, key, aad: aad, nonce: nonce);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

### 📋 Detached Mode (Manual Nonce)

```csharp
Span<byte> key = stackalloc byte[XChaCha20Poly1305.KeyLen];
Span<byte> nonce = stackalloc byte[XChaCha20Poly1305.NonceLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(nonce);

var plaintext = Encoding.UTF8.GetBytes("Detached encryption");
Span<byte> ciphertext = stackalloc byte[plaintext.Length];
Span<byte> mac = stackalloc byte[XChaCha20Poly1305.MacLen];

XChaCha20Poly1305.Encrypt(ciphertext, plaintext, key, mac, nonce: nonce);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
XChaCha20Poly1305.Decrypt(decrypted, ciphertext, key, mac, nonce: nonce);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

---

## ⚠️ Error Handling

- `ArgumentException` — invalid input sizes.
- `LibSodiumException` — authentication failed (tampered data).

---

## 📝 Notes

- Nonce must be exactly 24 bytes.
- Auto-nonce is prepended to ciphertext for easy reuse.
- Buffers must have space for output (e.g., ciphertext includes MAC and possibly nonce). It can be longer than needed.
- `Encrypt` and `Decrypt` automatically choose combined or detached mode depending on the presence of the `mac` parameter.
- Use `RandomGenerator.Fill()` to safely generate keys and nonces.
- AAD is optional but recommended for additional authentication context.

---

## 👀 See Also

- [libsodium AEAD documentation](https://doc.libsodium.org/secret-key_cryptography/aead)
- [RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439)
- [API Reference](../api/LibSodium.XChaCha20Poly1305.yml)

