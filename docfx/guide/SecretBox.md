# 🔒 SecretBox

The `SecretBox` API in **LibSodium.Net** provides a simple and secure way to perform symmetric authenticated encryption using the XSalsa20 stream cipher and Poly1305 MAC. It supports both **combined** and **detached** encryption modes, as well as **manual** or **automatic** nonce handling.

> 🧂Based on libsodium's [Authenticated encryption using `crypto_secretbox`](https://doc.libsodium.org/secret-key_cryptography/secretbox)<br/>
> ℹ️ *See also*: [API Reference for `SecretBox`](../api/LibSodium.SecretBox.yml)

---

## ✨ Features

- Symmetric authenticated encryption using XSalsa20-Poly1305.
- Combined mode and detached mode support.
- Automatic or manual nonce handling.
- Built-in MAC verification (tamper detection).
- Safe and efficient API using `Span<T>`.

---

## 🔍 Understanding Combined vs Detached Modes

The `SecretBox` API offers two encryption modes:

- **Combined Mode**: the MAC (Message Authentication Code) is prepended to the ciphertext. The output is a single buffer that contains both the encrypted message and the MAC.
  > Useful when you want to store or transmit ciphertext as one self-contained block.

- **Detached Mode**: the MAC is stored separately from the ciphertext. You get two outputs: one for the encrypted message, and one for the MAC.
  > Useful when your protocol has a separate field for authentication tags.

Nonce handling options:

- **Manual Nonce**: you provide a secure random nonce. Gives you full control but requires ensuring **nonces are never reused** with the same key.
- **Automatic Nonce**: the library generates a secure nonce and prepends it to the output.

> ⚠️ Reusing a nonce with the same key breaks security. Always use a fresh random nonce.

---

## 📦 Encrypting and Decrypting Messages

### 💻 Combined Mode (Manual Nonce)

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

### 💻 Combined Mode (Auto Nonce)

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

### 💻 Detached Mode (Manual Nonce)

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

### 💻 Detached Mode (Auto Nonce)

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

- `ArgumentException` — invalid input sizes.
- `LibSodiumException` — authentication failed.

---

## 📝 Notes

- Always use a **new random nonce** for each encryption if you're not using auto-nonce.
- Combined mode includes both MAC and ciphertext in a single buffer.
- Detached mode outputs MAC separately — useful for protocols with separate fields.
- Nonce must be exactly `SecretBox.NonceLen` bytes.
- Use `RandomGenerator.Fill()` for secure key and nonce generation.

