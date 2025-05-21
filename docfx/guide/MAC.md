# 📜 MAC Algorithms

Message Authentication Codes (MACs) provide **integrity** and **authenticity** for messages by allowing the recipient to verify that the data was produced by someone holding the secret key.

All code examples are written in the C# language and use LibSodium.Net’s allocation-free API.

Unlike encryption, **authentication** doesn't hide the contents of a message. It ensures that the message has **not been tampered with** and was created by someone who **knows the shared secret key**.

LibSodium.Net exposes three HMAC‑SHA‑2 variants and Poly1305 that cover the vast majority of real‑world requirements while staying allocation‑free and AOT‑friendly.


> 🧂 Based on libsodium’s [HMAC‑SHA‑2](https://doc.libsodium.org/advanced/hmac-sha2)<br/>
> 🧂 Based on libsodium’s [One-time authentication](https://doc.libsodium.org/advanced/poly1305)<br/>
> ℹ️ [API Reference: CryptoHmacSha256](../api/LibSodium.CryptoHmacSha256.yml)<br/>
> ℹ️ [API Reference: CryptoHmacSha512](../api/LibSodium.CryptoHmacSha512.yml)<br/>
> ℹ️ [API Reference: CryptoHmacSha512\_256](../api/LibSodium.CryptoHmacSha512_256.yml)<br/>
> ℹ️ [API Reference: CryptoOneTimeAuth](../api/LibSodium.CryptoOneTimeAuth.yml)<br/>

---

## 🌟 Features

* **Keyed authentication** with proven constructions (HMAC‑SHA‑2 & Poly1305).
* Allocation‑free `Span<T>` API + streaming + async overloads (HMACs).
* Unified method names: `ComputeMac`, `VerifyMac`, `GenerateKey`.
* Safe size checks that throw early (`ArgumentException`).
* Deterministic output – same key + message ⇒ same tag.

---

## ⚖️ Algorithm Comparison (bytes)

| API                    | Hash / Primitive | MacLen | KeyLen | Recommended Use‑Case                                                             |
| ---------------------- | ---------------- | ------ | ------ | -------------------------------------------------------------------------------- |
| `CryptoHmacSha256`     | SHA‑256          | 32     | 32     | Interop with systems expecting HMAC‑SHA‑256 (JWT, TLS, S3).                      |
| `CryptoHmacSha512`     | SHA‑512          | 64     | 32     | Larger tag & usually faster on 64‑bit CPUs.                                      |
| `CryptoHmacSha512_256` | SHA‑512/256      | 32     | 32     | 32‑byte tag with SHA‑512 speed & security margin.                                |
| `CryptoOneTimeAuth`    | Poly1305         | 16     | 32     | One‑time MAC for single‑key usage (AEAD internals, per‑message keys, SecretBox). |

---

## ✨ HMAC‑SHA‑256

The `CryptoHmacSha256` API implements HMAC-SHA-256 —built on the widely-deployed SHA-256 hash function— producing a 32-byte tag with a fixed 32-byte key. Choose this when you are interacting with external systems that require HMAC-SHA-256 (e.g., AWS S3 signatures, JWT HS256 tokens, many REST APIs).

### 📏 Constants

| Name     | Value | Description                            |
| -------- | ----- | -------------------------------------- |
| `MacLen` | 32    | Length of the authentication tag (32). |
| `KeyLen` | 32    | Length of the secret key (32).         |

---

## ✨ HMAC‑SHA‑512

The `CryptoHmacSha512` API implements HMAC-SHA-512 —producing a 64-byte tag with a fixed 32-byte key— and leverages SHA-512, which is typically faster than SHA-256 on modern 64-bit CPUs thanks to wider 64-bit arithmetic. Choose this variant when tag length isn’t constrained and you want the largest security margin (the 64-byte tag halves collision probability compared to 32-byte tags).

### 📏 Constants

| Name     | Value | Description                            |
| -------- | ----- | -------------------------------------- |
| `MacLen` | 64    | Length of the authentication tag (64). |
| `KeyLen` | 32    | Length of the secret key (32).         |

---

## ✨ HMAC‑SHA‑512/256

The `CryptoHmacSha512_256` API implements HMAC-SHA-512/256. It is not “SHA-256”; it re-uses SHA-512’s wide pipeline but truncates to 256 bits, producing a 32-byte tag with a fixed 32-byte key while retaining the performance of SHA-512. Use this variant when you need SHA-256-sized output yet can rely on SHA-512 acceleration in your environment (typically 64-bit CPUs).

### 📏 Constants

| Name     | Value | Description                            |
| -------- | ----- | -------------------------------------- |
| `MacLen` | 32    | Length of the authentication tag (32). |
| `KeyLen` | 32    | Length of the secret key (32).         |

---

## ✨ Poly1305

The `CryptoOneTimeAuth` API implements Poly1305. It is an extremely fast, **one-time** authenticator designed by D. J. Bernstein, authenticating a message with a fixed single-use 32-byte key and producing a compact 16-byte tag.

Use cases include:

* **AEAD constructions** – e.g. ChaCha20‑Poly1305, XChaCha20‑Poly1305, XSalsa20‑Poly1305 (SecretBox)
* Authenticating short messages when you can derive a fresh key per message
* Implementing high‑speed, one‑shot integrity checks inside protocols

> ⚠️ **Key reuse breaks security.** Each key must be used to authenticate *one* message only. Derive a new random key (or sub‑key) per message.

### 📏 Constants

| Name     | Value | Description                            |
| -------- | ----- | -------------------------------------- |
| `MacLen` | 16    | Length of the authentication tag (16). |
| `KeyLen` | 32    | Length of the secret key (32).         |

---

## 🗝️ Key Management Tips

* Generate a fresh random key with `GenerateKey` and store it securely (e.g., Azure Key Vault, environment variable, HSM).
* **Never** reuse keys across different algorithms or protocols.
* Rotate keys periodically and re‑compute MACs for stored data when you do.
* Don't reuse keys in `CryptoOneTimeAuth`.

---

## 📋 Usage Example 

```csharp
using System.Diagnostics;

// Async overloads accept Memory<byte>/ReadOnlyMemory<byte>, not Span<byte>.
// We use byte[] because it implicitly converts to both Memory<byte> and Span<byte>.
byte[] key = new byte[CryptoHmacSha256.KeyLen];
byte[] mac = new byte[CryptoHmacSha256.MacLen];

CryptoHmacSha256.GenerateKey(key);

// UTF‑8 string literal (.NET 8+)
ReadOnlySpan<byte> message = "hello"u8; 

// Calculate MAC
CryptoHmacSha256.ComputeMac(key, message, mac);

// Verify MAC
bool ok = CryptoHmacSha256.VerifyMac(key, message, mac);
Debug.Assert(ok);

// Stream example (sync)
using var stream = File.OpenRead("file.bin");
CryptoHmacSha256.ComputeMac(key, stream, mac);
stream.Position = 0; // rewind
bool okStream = CryptoHmacSha256.VerifyMac(key, stream, mac);
Debug.Assert(okStream);

// Stream example (async)
stream.Position = 0;
await CryptoHmacSha256.ComputeMacAsync(key, stream, mac);
stream.Position = 0;
bool okStreamAsync = await CryptoHmacSha256.VerifyMacAsync(key, stream, mac);
Debug.Assert(okStreamAsync);

```

> ℹ️ **Same API across algorithms** – swap the class name to change the MAC primitive.

---

## 🧭 Choosing the Right MAC

| Scenario                                                              | Recommendation                              |
| --------------------------------------------------------------------- | ------------------------------------------- |
| Interop with JWT HS256 / Web APIs                                     | `CryptoHmacSha256`                          |
| Internal service‑to‑service messages on x64 servers                   | `CryptoHmacSha512`                          |
| Need 32‑byte tag but favour SHA‑512 performance                       | `CryptoHmacSha512_256`                      |
| Authenticating AEAD ciphertext / per‑packet tag with derived sub‑key  | `CryptoOneTimeAuth`                         |
| Very short messages (< 64 B) & performance critical, one‑time setting | `CryptoOneTimeAuth`                         |
| Long‑term shared key, multi‑message scenario                          | Any HMAC variant (avoid Poly1305 key reuse) |


---

## ⚠️ Error Handling

| Condition                       | Exception            |
| ------------------------------- | -------------------- |
| Key or MAC buffer wrong length  | `ArgumentException`  |
| Stream read fails / internal RC | `LibSodiumException` |

---

## 📝 Notes

* All APIs are **deterministic**: same key + message ⇒ same MAC.
* Verification is **constant‑time** to avoid timing attacks.
* The secret key length is fixed (32).

---

## 👀 See Also

* 🧂 [libsodium HMAC‑SHA‑2](https://doc.libsodium.org/advanced/hmac-sha2)
* 🧂 [libsodium One-time authentication](https://doc.libsodium.org/advanced/poly1305)
* ℹ️ [API Reference: CryptoHmacSha256](../api/LibSodium.CryptoHmacSha256.yml)
* ℹ️ [API Reference: CryptoHmacSha512](../api/LibSodium.CryptoHmacSha512.yml)
* ℹ️ [API Reference: CryptoHmacSha512\_256](../api/LibSodium.CryptoHmacSha512_256.yml)
* ℹ️ [API Reference: CryptoOneTimeAuth](../api/LibSodium.CryptoOneTimeAuth.yml)
