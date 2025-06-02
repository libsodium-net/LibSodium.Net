# 🔒 Stream Ciphers

Stream ciphers provide **confidentiality** for messages of any length —short or long— turning data into a sequence indistinguishable from random noise.
They operate on fixed-size blocks of data, using minimal memory, which makes them perfect for real-time streams, huge files, or jumping directly to any part of a message without processing everything before it.

**How they work:** A stream cipher generates a pseudorandom sequence called the *keystream* from a secret *key* and a fresh *nonce*, then combines it with the plaintext or ciphertext using XOR to encrypt or decrypt; the operation is symmetric, so the same process is used for both encryption and decryption.

⚠️ **No built-in authentication**: Stream ciphers only provide confidentiality. They do *not* protect against tampering — an attacker can flip bits undetected. Always combine with a MAC (e.g., Poly1305) or use an AEAD construction
 when integrity or authenticity matters.

Why use them?

* Works on the fly: ideal for live audio, video, chat, or sensor feeds.
* Minimal buffering: great for very large files or constrained devices.
* Random access: you can decrypt any block independently.

Beyond encryption you can treat the keystream itself as a fast **pseudorandom function (PRF)** for masking or key‑derivation tasks.

> 🧂 Based on libsodium’s [Stream ciphers](https://doc.libsodium.org/advanced/stream_ciphers)<br/>
> ℹ️ [API Reference: CryptoStreamXSalsa20](../api/LibSodium.CryptoStreamXSalsa20.yml)<br/>
> ℹ️ [API Reference: CryptoStreamSalsa20](../api/LibSodium.CryptoStreamSalsa20.yml)<br/>
> ℹ️ [API Reference: CryptoStreamChaCha20](../api/LibSodium.CryptoStreamChaCha20.yml)<br/>
> ℹ️ [API Reference: CryptoStreamChaCha20Ietf](../api/LibSodium.CryptoStreamChaCha20Ietf.yml)<br/>
> ℹ️ [API Reference: CryptoStreamXChaCha20](../api/LibSodium.CryptoStreamXChaCha20.yml)

---

## 🌟 Features

* **Allocation‑free `Span<T>` API** plus streaming & `async` overloads.
* Unified method names: `Encrypt`, `Decrypt`, `GenerateKeystream`.
* Supports encryption and decryption starting at a given block index (`initialCounter`).
* Key & nonce length checks throw early (`ArgumentException`).
* Deterministic: same key + nonce ⇒ same keystream.
* Huge keystream period: 2^64 blocks ≈ 2^70 bytes —except for the IETF variant— *practically* limitless but **not infinite**.
* Accepts `SecureMemory<byte>` as key input.

---

## ✨ Common API

All stream cipher classes share the following members:

| Member              | Type     | Description                                                                     |
| ------------------- | -------- | ------------------------------------------------------------------------------- |
| `KeyLen`            | Constant | Length of the secret key in bytes.                                              |
| `NonceLen`          | Constant | Length of the nonce in bytes.                                                   |
| `BlockLen`          | Constant | Keystream block size in bytes.                                                  |
| `Encrypt`           | Method   | Encrypts data using key and nonce. Applies to both span-based and stream-based. |
| `Decrypt`           | Method   | Decrypts data using key and nonce. Applies to both span-based and stream-based. |
| `GenerateKeystream` | Method   | Generates keystream into an output buffer using key and nonce.                  |
| `EncryptAsync`      | Method   | Asynchronously encrypts stream input to stream output with key and nonce.       |
| `DecryptAsync`      | Method   | Asynchronously decrypts stream input to stream output with key and nonce.       |


## ⚖️ Algorithm Comparison

| API                        | KeyLen | NonceLen | BlockLen | Keystream Period                |
| -------------------------- | ------ | -------- | -------- | ------------------------------- |
| `CryptoStreamXSalsa20`     | 32     | 24       | 64       | 2⁶⁴ blocks = 1 ZiB              |
| `CryptoStreamSalsa20`      | 32     | 8        | 64       | 2⁶⁴ blocks = 1 ZiB              |
| `CryptoStreamChaCha20`     | 32     | 8        | 64       | 2⁶⁴ blocks = 1 ZiB              |
| `CryptoStreamChaCha20Ietf` | 32     | 12       | 64       | 2³² blocks = 256 GiB            |
| `CryptoStreamXChaCha20`    | 32     | 24       | 64       | 2⁶⁴ blocks = 1 ZiB              |

> KeyLen, NonceLen, and BlockLen are in bytes.

---

## 🧭 Choosing the Right Stream Cipher

| Scenario                                             | Recommendation                    |
| ---------------------------------------------------- | --------------------------------- |
| Random nonces, enormous message count                | `CryptoStreamXChaCha20`           |
| Interop with RFC 8439 / HTTP / QUIC                  | `CryptoStreamChaCha20Ietf`        |
| NaCl / libsodium pre‑2018 compatibility              | `CryptoStreamXSalsa20` or Salsa20 |
| Embedded / resource‑constrained but need ChaCha core | `CryptoStreamChaCha20`            |
| **Never reuse nonces** & bounded message number      | Any variant (pick nonce length)   |

---

## 📋 Usage Example

All examples are in C# and work for all stream cipher algorithms, just change the class name.

LibSodium.Net accepts `Span<byte>`/`ReadOnlySpan<byte>`, `byte[]`, or `SecureMemory<byte>` as key inputs for synchronous methods.
For asynchronous methods, it accepts `Memory<byte>`/`ReadOnlyMemory<byte>`, `byte[]`, or `SecureMemory<byte>`.

Using `SecureMemory<byte>` is strongly recommended, as it protects key material in unmanaged memory with automatic zeroing and access control.

```csharp
// Async overloads accept Memory<byte>/ReadOnlyMemory<byte>, not Span<byte>.
// We use byte[] because it implicitly converts to both Memory<byte> and Span<byte>.
byte[] key = new byte[CryptoStreamXChaCha20.KeyLen];
RandomGenerator.Fill(key);
```

```csharp
// SecureMemory works for both synchronous and asynchronous methods.
using var key = new SecureMemory<byte>(CryptoStreamXChaCha20.KeyLen);
RandomGenerator.Fill(key);
key.ProtectReadOnly();
```

Use `RandomGenerator.Fill()` to generate a cryptographically secure random key. 
Alternatively, keys may be securely stored or derived using a key derivation function.

```csharp

byte[] nonce = new byte[CryptoStreamXChaCha20.NonceLen];
RandomGenerator.Fill(nonce);

// 1. Basic usage encrypt and decrypt buffer
ReadOnlySpan<byte> plaintext = "secret"u8;
// Encrypting a buffer:
byte[] ciphertext = new byte[plaintext.Length];
CryptoStreamXChaCha20.Encrypt(key, nonce, plaintext, ciphertext);
// Decrypting a buffer:
byte[] decrypted = new byte[ciphertext.Length];
CryptoStreamXChaCha20.Decrypt(key, nonce, ciphertext, decrypted);

// Check that the decrypted buffer matches the original plaintext
Debug.Assert(plaintext.SequenceEqual(decrypted));

// 2. Stream-based (sync)
using (var inputFile = File.OpenRead("video.raw"))
using (var encryptedFile = File.Create("video.enc"))
using (var decryptedFile = File.Create("video.dec"))
{
	// Encrypting a file:
	CryptoStreamXChaCha20.Encrypt(key, nonce, inputFile, encryptedFile);
	// Decrypting a file:
	encryptedFile.Position = 0; // Reset the position of the encrypted file to the beginning
	CryptoStreamXChaCha20.Decrypt(key, nonce, encryptedFile, decryptedFile);
}

// 3. Stream-based (async)
using (var inputFile = File.OpenRead("video.raw"))
using (var encryptedFile = File.Create("video.enc"))
using (var decryptedFile = File.Create("video.dec"))
{
	// Encrypting a file:
	await CryptoStreamXChaCha20.EncryptAsync(key, nonce, inputFile, encryptedFile);
	// Decrypting a file:
	encryptedFile.Position = 0; // Reset the position of the encrypted file to the beginning
	await CryptoStreamXChaCha20.DecryptAsync(key, nonce, encryptedFile, decryptedFile);
}

// 4. Generate raw keystream
Span<byte> keystream = stackalloc byte[128];
CryptoStreamXChaCha20.GenerateKeystream(keystream, nonce, key);

// 5. Start encryption/decryption from a specific block index (e.g., resume or skip)
CryptoStreamXChaCha20.Encrypt(key, nonce, plaintext, ciphertext, initialCounter: 10);
CryptoStreamXChaCha20.Decrypt(key, nonce, ciphertext, decrypted, initialCounter: 10);
```

---

## ⚠️ Error Handling

| Condition                       | Exception            |
| ------------------------------- | -------------------- |
| Wrong key / nonce length        | `ArgumentException`  |
| Output buffer too small         | `ArgumentException`  |
| I/O failure in stream overloads | `LibSodiumException` |

---

## 🗝️ Key & Nonce Management Tips

* **Never** reuse a nonce with the same key—this reveals keystream and breaks confidentiality.
* Prefer 24‑byte variants for random nonces; use counters for 8/12‑byte variants.
* Use `SecureMemory<byte>` for keys. It provides guarded heap allocations with memory protection and automatic wiping.

---

## 📝 Notes

* Stream ciphers offer **no built‑in authentication**, pair them with a MAC (Poly1305/HMAC) or use an AEAD construction.
* Keystream period is 2^64 blocks (64 bytes each), except `CryptoStreamChaCha20Ietf` with 2^32.
* All APIs are constant‑time with respect to secret data.

---

## 👀 See Also

* 🧂 [Stream ciphers](https://doc.libsodium.org/advanced/stream_ciphers)
* ℹ️ [API Reference: CryptoStreamXSalsa20](../api/LibSodium.CryptoStreamXSalsa20.yml)
* ℹ️ [API Reference: CryptoStreamSalsa20](../api/LibSodium.CryptoStreamSalsa20.yml)
* ℹ️ [API Reference: CryptoStreamChaCha20](../api/LibSodium.CryptoStreamChaCha20.yml)
* ℹ️ [API Reference: CryptoStreamChaCha20Ietf](../api/LibSodium.CryptoStreamChaCha20Ietf.yml)
* ℹ️ [API Reference: CryptoStreamXChaCha20](../api/LibSodium.CryptoStreamXChaCha20.yml)
