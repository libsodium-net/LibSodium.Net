# 🔒 SecretBox

The `SecretBox` API in **LibSodium.Net** provides a simple and secure way to perform symmetric authenticated encryption using the XSalsa20 stream cipher and Poly1305 MAC. It supports both **combined** and **detached** encryption modes, as well as **manual** or **automatic** nonce handling — all from a single, unified API.

> 🧂Based on libsodium's [Authenticated encryption using `crypto_secretbox`](https://doc.libsodium.org/secret-key_cryptography/secretbox)<br/>
> ℹ️ *See also*: [API Reference for `SecretBox`](../api/LibSodium.SecretBox.yml)

---

## ✨ Features

- Symmetric authenticated encryption using XSalsa20-Poly1305.
- Combined mode and detached mode support.
- Automatic or manual nonce handling.
- Built-in MAC verification (tamper detection).
- Unified `Encrypt` / `Decrypt` API with optional parameters.
- Safe and efficient `Span<T>`-based implementation.

---

## 📦 Encrypting and Decrypting Messages

Use the `Encrypt` and `Decrypt` methods. The behavior depends on whether you pass a `mac` buffer (detached) and/or a `nonce` (manual).

### 💻 Combined Mode (Auto Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
RandomGenerator.Fill(key);

var plaintext = Encoding.UTF8.GetBytes("Hello, auto-nonce world!");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + SecretBox.MacLen + SecretBox.NonceLen];

SecretBox.Encrypt(ciphertext, plaintext, key);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
SecretBox.Decrypt(decrypted, ciphertext, key);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

### 💻 Combined Mode (Manual Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
Span<byte> nonce = stackalloc byte[SecretBox.NonceLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(nonce);

var plaintext = Encoding.UTF8.GetBytes("Manual nonce combined");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + SecretBox.MacLen];

SecretBox.Encrypt(ciphertext, plaintext, key, nonce: nonce);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
SecretBox.Decrypt(decrypted, ciphertext, key, nonce: nonce);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

### 💻 Detached Mode (Auto Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
RandomGenerator.Fill(key);

var plaintext = Encoding.UTF8.GetBytes("Detached + auto nonce");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + SecretBox.NonceLen];
Span<byte> mac = stackalloc byte[SecretBox.MacLen];

SecretBox.Encrypt(ciphertext, plaintext, key, mac);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
SecretBox.Decrypt(decrypted, ciphertext, key, mac);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

### 💻 Detached Mode (Manual Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
Span<byte> nonce = stackalloc byte[SecretBox.NonceLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(nonce);

var plaintext = Encoding.UTF8.GetBytes("Detached with nonce");
Span<byte> ciphertext = stackalloc byte[plaintext.Length];
Span<byte> mac = stackalloc byte[SecretBox.MacLen];

SecretBox.Encrypt(ciphertext, plaintext, key, mac, nonce);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
SecretBox.Decrypt(decrypted, ciphertext, key, mac, nonce);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

---

## ⚠️ Error Handling

- `ArgumentException` — invalid input sizes.
- `LibSodiumException` — authentication failed.

---

## 📝 Notes

- Nonce must be exactly `SecretBox.NonceLen` bytes when passed manually.
- Auto-nonce is prepended to the ciphertext when not specified.
- Combined mode outputs ciphertext + MAC (+ optional nonce).
- Detached mode separates MAC from ciphertext.
- Buffers can be larger than required.
- Always use `RandomGenerator.Fill()` for secure key and nonce generation.

---

## 👀 See Also

- [libsodium secretbox documentation](https://doc.libsodium.org/secret-key_cryptography/secretbox)
- [API Reference](../api/LibSodium.SecretBox.yml)
