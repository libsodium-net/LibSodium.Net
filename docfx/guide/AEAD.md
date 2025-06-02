# 🔐 AEAD Algorithms

LibSodium.Net provides a unified API for all AEAD (Authenticated Encryption with Associated Data) constructions available in libsodium. These algorithms offer both confidentiality and authenticity, and support optional additional data (AAD) for contextual authentication.

Each algorithm supports both **combined mode** (MAC is part of the ciphertext) and **detached mode** (MAC is separate), and allows **automatic** or **manual** nonce handling.

> 🧂 Based on libsodium's [AEAD constructions](https://doc.libsodium.org/secret-key_cryptography/aead)

---

## ⚖️ Algorithm Comparison (len in bytes)

| Algorithm                                                           | KeyLen | NonceLen | MacLen |
| ------------------------------------------------------------------- | ------ | -------- | ------ |
| [XChaCha20-Poly1305](../api/LibSodium.XChaCha20Poly1305.yml)        | 32     | 24       | 16     |
| [ChaCha20-Poly1305-IETF](../api/LibSodium.ChaCha20Poly1305Ietf.yml) | 32     | 12       | 16     |
| [ChaCha20-Poly1305](../api/LibSodium.ChaCha20Poly1305.yml)          | 32     | 8        | 16     |
| [AES256-GCM](../api/LibSodium.Aes256Gcm.yml)                        | 32     | 12       | 16     |
| [AEGIS-256](../api/LibSodium.Aegis256.yml)                          | 32     | 32       | 32     |
| [AEGIS-128L](../api/LibSodium.Aegis128L.yml)                        | 32     | 16       | 32     |

---

## 🗝️ Encrypting and Decrypting

Use the `Encrypt` and `Decrypt` methods from any `LibSodium.<Algorithm>` class. The API automatically chooses **combined** or **detached** mode based on the presence of the optional `mac` parameter.

All AEAD algorithms share the same API:

```csharp
// With ReadOnlySpan<byte> key
public static Span<byte> Encrypt(
    Span<byte> ciphertext,
    ReadOnlySpan<byte> plaintext,
    ReadOnlySpan<byte> key,
    Span<byte> mac = default,
    ReadOnlySpan<byte> aad = default,
    ReadOnlySpan<byte> nonce = default);

public static Span<byte> Decrypt(
    Span<byte> plaintext,
    ReadOnlySpan<byte> ciphertext,
    ReadOnlySpan<byte> key,
    ReadOnlySpan<byte> mac = default,
    ReadOnlySpan<byte> aad = default,
    ReadOnlySpan<byte> nonce = default)
```

```csharp
// With SecureMemory<byte> key
public static Span<byte> Encrypt(
    Span<byte> ciphertext,
    ReadOnlySpan<byte> plaintext,
    SecureMemory<byte> key,
    Span<byte> mac = default,
    ReadOnlySpan<byte> aad = default,
    ReadOnlySpan<byte> nonce = default);

public static Span<byte> Decrypt(
    Span<byte> plaintext,
    ReadOnlySpan<byte> ciphertext,
    SecureMemory<byte> key,
    ReadOnlySpan<byte> mac = default,
    ReadOnlySpan<byte> aad = default,
    ReadOnlySpan<byte> nonce = default)
```

`ReadOnlySpan<byte>`, `byte[]` and `SecureMemory<byte>` are accepted as key inputs.

Optional parameters allow for ergonomic usage while retaining full control. Using named arguments for optional ones is highly recommended.

---

## 📋 AEGIS-256 example

AEGIS-256 (Combined mode with auto nonce and AAD)

```csharp
Span<byte> key = stackalloc byte[Aegis256.KeyLen];
RandomGenerator.Fill(key);

var plaintext = Encoding.UTF8.GetBytes("Secret message");
var aad = Encoding.UTF8.GetBytes("authenticated context");

var ciphertext = new byte[plaintext.Length + Aegis256.MacLen + Aegis256.NonceLen];
Aegis256.Encrypt(ciphertext, plaintext, key, aad: aad);

var decrypted = new byte[plaintext.Length];
Aegis256.Decrypt(decrypted, ciphertext, key, aad: aad);

SecureMemory.MemZero(key);

Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

---

## 📋 ChaCha20-Poly1305 example

ChaCha20-Poly1305 (Combined mode with AAD, incrementing manual nonce to prevent reuse)

```csharp
Span<byte> key = stackalloc byte[ChaCha20Poly1305.KeyLen];
Span<byte> nonce = stackalloc byte[ChaCha20Poly1305.NonceLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(nonce);

var aad = Encoding.UTF8.GetBytes("v1");

var message1 = Encoding.UTF8.GetBytes("First message");
var ciphertext1 = new byte[message1.Length + ChaCha20Poly1305.MacLen];
ChaCha20Poly1305.Encrypt(ciphertext1, message1, key, aad: aad, nonce: nonce);

SecureBigUnsignedInteger.Increment(nonce); // increment to prevent reuse (nonce is only 8 bytes)

var message2 = Encoding.UTF8.GetBytes("Second message");
var ciphertext2 = new byte[message2.Length + ChaCha20Poly1305.MacLen];
ChaCha20Poly1305.Encrypt(ciphertext2, message2, key, aad: aad, nonce: nonce);

SecureMemory.MemZero(key);
```

## 📋 AES256-GCM example

AES256-GCM (SecureMemory, detached MAC, autononce, no AAD)

```csharp
using var key = new SecureMemory<byte>(Aes256Gcm.KeyLen);
Span<byte> nonce = stackalloc byte[Aes256Gcm.NonceLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(nonce);
key.ProtectReadOnly();

Span<byte> ciphertext = new byte[plaintext.Length];
Span<byte> mac = stackalloc byte[Aes256Gcm.MacLen];

Aes256Gcm.Encrypt(ciphertext, plaintext, key, mac: mac);

Span<byte> decrypted = new byte[plaintext.Length];
Aes256Gcm.Decrypt(decrypted, ciphertext, key, mac: mac);
```


---

## ⚠️ Error Handling

* `ArgumentException` — invalid input lengths or buffer sizes.
* `LibSodiumException` — authentication failure (e.g., tampered data).

---

## 📝 Notes

* All optional parameters (`mac`, `aad`, `nonce`) should be passed using **named arguments** for clarity and safety (e.g., `aad: data`).
* Nonces must match the algorithm's required length.
* If omitted, a random nonce is generated automatically and prepended to the ciphertext.
* Buffers must be large enough to hold output.
* AAD is optional and not a secret. If provided it must the same for both encryption and decryption.
* Nonce is optional and not a secret. If not provided (automatic nonce) it is randomly generated and prepended to the ciphertext. If provided (manual nonce) it must be the same for both encryption and decryption.
* MAC is optional and not a secret. If not provided (combined mode) it is included within the ciphertext. If provided (detached mode) it must be the same for both encryption and decryption.
- Use `RandomGenerator.Fill()` to generate cryptographically secure random keys and nonces. Alternatively, keys may be securely stored or derived using a key derivation function.
- Use `SecureMemory<byte>` for keys.

---

## 👀 See Also

* [libsodium AEAD constructions](https://doc.libsodium.org/secret-key_cryptography/aead)
* [API Reference](../api/LibSodium.yml)
