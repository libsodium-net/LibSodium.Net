# 🔑 Key Derivation in LibSodium.Net

LibSodium.Net provides three powerful primitives for key derivation:

* `CryptoKeyDerivation`: libsodium's native KDF built on BLAKE2b.
* `CryptoHChaCha20`: a fast, stateless KDF based on the HChaCha20 core function.
* `CryptoHkdf`: a standard HKDF implementation based on HMAC (SHA-256 or SHA-512).


> 🧂 Based on libsodium's [Key derivation](https://doc.libsodium.org/key_derivation)<br/>
> 🧂 Based on libsodium's [HKDF](https://doc.libsodium.org/key_derivation/hkdf)<br/>
> ℹ️ *See also*: [API Reference for `CryptoKeyDerivation`](../api/LibSodium.CryptoKeyDerivation.yml)<br/>
> ℹ️ *See also*: [API Reference for `HKDF`](../api/LibSodium.CryptoHkdf.yml)<br/>
> ℹ️ *See also*: [API Reference for `CryptoHChaCha20`](../api/LibSodium.CryptoHChaCha20.yml)

This guide compares all options, shows how to choose between them, and offers practical usage advice.

---

## 📋 Primitives Comparative

| Feature                    | `CryptoKeyDerivation`               | `Hkdf`                                | `CryptoHChaCha20`                    |
| -------------------------- | ----------------------------------- | ------------------------------------- | ------------------------------------ |
| Algorithm                  | BLAKE2b                             | HMAC-SHA-256 / HMAC-SHA-512           | HChaCha20                            |
| Based on                   | `crypto_kdf_*` API                  | `crypto_kdf_hkdf_{sha256,sha512}`     | `crypto_core_hchacha20`              |
| Standard                   | No                                  | RFC 5869                              | No                                   |
| Derivation style           | Single-step                         | Extract-then-expand                   | Single-step                          |
| Inputs                     | masterKey, subkeyId, context        | ikm, salt, info                       | key, input, \[context]               |
| Deterministic              | Yes                                 | Yes                                   | Yes                                  |
| Performance                | Faster                              | Slower                                | Fastest                              |
| Interoperability           | Low                                 | High                                  | Medium (used in XChaCha20)           |
| Subkey uniqueness driver   | `ulong subkeyId` + 8-byte `context` | Arbitrary `salt` and `info`           | 16-byte `input` + optional `context` |
| Max identifier size        | 16 bytes total (id + context)       | Arbitrary                             | 32 bytes (input + context)           |
| Collisions with random IDs | Realistic risk                      | Practically zero (if inputs are long) | Low risk (if input is random)        |
| State requirement          | Yes (track last subkeyId)           | No                                    | No                                   |
| Stateless randomness       | Not safe                            | Safe                                  | Safe                                 |
| Best practice              | Use a database sequence             | Use long random salt/info             | Use random 16-byte input             |


---

### SHA-256 vs SHA-512 in HKDF

* SHA-256: smaller hash, historically faster on constrained environments (e.g., old ARM cores).
* SHA-512: stronger and typically faster on modern 64-bit CPUs due to optimized instructions and wider registers.

Use `SHA-512` unless you have specific compatibility or performance constraints.

---

## ✨ When to Use Each

### Choose `HKDF` when:

* You need RFC 5869 compliance.
* You want to avoid state tracking.
* You can safely randomize inputs (salt/info).
* You’re interoperating with non-libsodium systems.

### Choose `CryptoKeyDerivation` when:

* You need to derive many related subkeys (e.g., message sequence).
* You control the environment and want maximum speed.
* You can track `subkeyId` safely (e.g., in a DB or in-memory).

📝 Example: For a secure message stream, generate one random `subkeyId` per session, then increment it for each message. This yields high performance and unique keys.

### Choose `CryptoHChaCha20` when:

* You want **stateless deterministic** derivation from a master key.
* You need **nonce extension** for AES-GCM or similar AEAD schemes.
* You want **domain separation** via a fixed 16-byte context.

---

## ✨ `CryptoKeyDerivation`

This API is built on libsodium’s BLAKE2b-based `crypto_kdf_*` functions. It allows fast deterministic derivation of many subkeys from a single master key and a context+id pair.

### 📏 Constants

| Name           | Value | Description                        |
| -------------- | ----- | ---------------------------------- |
| `MasterKeyLen` | 32    | Length of master key (32 bytes)    |
| `ContextLen`   | 8     | Length of context string (8 bytes) |
| `MinSubkeyLen` | 16    | Minimum subkey length              |
| `MaxSubkeyLen` | 64    | Maximum subkey length              |

### 📋 Generate a master key

You can use  `CryptoKeyDerivation.GenerateMasterKey` to generate a cryptographically secure random master key. Alternatively, the key may be securely stored or derived.

Master key can be `SecureMemory<byte>`, `Span<byte>`, or `byte[]` (implicitly convertible to `Span<byte>`)

```csharp
// SecureMemory masterKey
using var masterKey = new SecureMemory<byte>(CryptoKeyDerivation.MasterKeyLen);
CryptoKeyDerivation.GenerateMasterKey(masterKey);
```

```csharp
// Span masterKey
Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
CryptoKeyDerivation.GenerateMasterKey(masterKey);
```

```csharp
// byte[] masterKey
var masterKey = new byte[CryptoKeyDerivation.MasterKeyLen];
CryptoKeyDerivation.GenerateMasterKey(masterKey);
```

### 📋 Derive a subkey

You derive a subkey from a master key, a subkey id and a context using `DeriveSubKey()` method. 
Subkeys can be `SecureMemory<byte>`, `Span<byte>`, or `byte[]` (implicitly convertible to `Span<byte>`)

```csharp
// SecureMemory subkey
using var subkey = new SecureMemory<byte>(32);
CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 42, "MYCTX");
```

```csharp
// Span subkey
Span<byte> subkey = stackalloc byte[32];
CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 42, "MYCTX");
```

```csharp
// byte[] subkey
using var subkey = new byte[32];
CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 42, "MYCTX");
```

📝 Context must be exactly 8 bytes. Strings shorter than 8 are zero-padded.

---

## ✨ CryptoHChaCha20

`CryptoHChaCha20` provides fast, deterministic subkey derivation using the HChaCha20 function, originally designed for use in `XChaCha20`. It is suitable for nonce extension, domain separation and stateless derivation of subkeys from a master key.

🧂 Based on libsodium’s [`crypto_core_hchacha20`](https://doc.libsodium.org/advanced/stream_ciphers/xchacha20#key-derivation-with-hchacha20)
ℹ️ [API Reference: `CryptoHChaCha20`](../api/LibSodium.CryptoHChaCha20.yml)

---

### 📏 Constants

| Name         | Value | Description                           |
| ------------ | ----- | ------------------------------------- |
| `KeyLen`     | 32    | Length of the master key              |
| `InputLen`   | 16    | Length of the salt-like input         |
| `ContextLen` | 16    | Length of the optional domain context |
| `SubKeyLen`  | 32    | Length of the derived subkey          |

---

### 📋 Derive a subkey

You can derive a 32-byte subkey using a 32-byte master key and a 16-byte input. You may optionally provide a 16-byte domain context.

```csharp
using var  subKey = new SecureMemory<byte>(CryptoHChaCha20.SubKeyLen);
using var  key =  new SecureMemory<byte>(CryptoHChaCha20.KeyLen);
Span<byte> input = stackalloc byte[CryptoHChaCha20.InputLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(input);

CryptoHChaCha20.DeriveSubkey(key, subKey, input, "app-context");
```

---

### 📋 Example: AES256-GCM nonce extension

HChaCha20 can be used to securely extend a nonce for AES256-GCM:

```csharp
// this is a sample to demonstrate nonce extension using HChaCha20
// it extends a 12-byte AES256-GCM nonce into a 28-byte nonce


Span<byte> key = Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

// 16 + 12 = 28 bytes total
Span<byte> extendedNonce = stackalloc byte[CryptoHChaCha20.InputLen + Aes256Gcm.NonceLen];
RandomGenerator.Fill(extendedNonce);

Span<byte> subkey = stackalloc byte[CryptoHChaCha20.SubKeyLen];

// first 16 bytes of nonce are used as input to derive the subkey
var input = extendedNonce.Slice(0, CryptoHChaCha20.InputLen);
CryptoHChaCha20.DeriveSubkey(key, subkey, input);

		
ReadOnlySpan<byte> plaintext = "some plaintext data to encrypt"u8;
Span<byte> ciphertext = stackalloc byte[plaintext.Length + Aes256Gcm.MacLen];
// the next 12 bytes of extended nonce are used as the AES256-GCM nonce
var nonce = extendedNonce.Slice(CryptoHChaCha20.InputLen, Aes256Gcm.NonceLen);

Aes256Gcm.Encrypt(ciphertext, plaintext, subkey, nonce: nonce);
```
---

## ✨ `HKDF`

`HKDF` implements RFC 5869 using HMAC-SHA-256 or HMAC-SHA-512. It is compatible with `System.Security.Cryptography.HKDF.DeriveKey` and produces identical outputs when the inputs match.

📝 LibSodium.Net's `HKDF` is fully interoperable with `System.Security.Cryptography.HKDF` from .NET — both produce identical outputs when using the same inputs and hash algorithm.

Key, IKM (Initial Key Material), PRK (Pseudo-Random Key), and OKM (Output Key Material) can be provided as `SecureMemory<byte>`, `Span<byte>` / `ReadOnlySpan<byte>`, or `byte[]` (implicitly convertible to `Span<byte>`) for synchronous methods.
For asynchronous streaming methods, use `SecureMemory<byte>`, `Memory<byte>` / `ReadOnlyMemory<byte>`, or `byte[]` (implicitly convertible to `Memory<byte>` / `ReadOnlyMemory<byte>`).


### 📏 Constants

| Name        | SHA256 | SHA512 | Description                              |
| ----------- | ------ | ------ | ---------------------------------------- |
| `PrkLen`    | 32     | 64     | Length of PRK (pseudorandom key)         |
| `MinOkmLen` | 4      | 4      | Minimum output length                    |
| `MaxOkmLen` | 8160   | 16320  | Maximum output length (255 \* hash size) |

### 🪄 HKDF Phases

* `Extract`: Converts input keying material (IKM) and salt into a pseudorandom key (PRK).
* `Expand`: Derives the final output key material (OKM) from the PRK and optional `info`.
* `DeriveKey`: Performs both steps in one call.

#### When to use which:

* Use `DeriveKey` for simple cases where no reuse of PRK is needed.
* Use `Extract` + `Expand` when you want to reuse PRK for multiple outputs.
* Use `Expand` when you already have a good master key.

### 📋 Derive a key in one step



```csharp
// Span key
Span<byte> key = stackalloc byte[64];
HKDF.DeriveKey(HashAlgorithmName.SHA512, ikm, key, salt, info);
```

```csharp
// SecureMemory key
using var key = new SecureMemory<byte>(64);
HKDF.DeriveKey(HashAlgorithmName.SHA512, ikm, key, salt, info);
```

### 📋 Separate extract and expand

```csharp
Span<byte> prk = stackalloc byte[HKDF.Sha512PrkLen];
HKDF.Extract(HashAlgorithmName.SHA512, ikm, salt, prk);

Span<byte> okm = stackalloc byte[64];
HKDF.Expand(HashAlgorithmName.SHA512, prk, okm, info);
```

### 📋 Extract from stream (incremental entropy)

This allows deriving a PRK from streamed IKM.

```csharp
using var stream = File.OpenRead("large-secret.bin");
var prk = new byte[HKDF.Sha512PrkLen];
await HKDF.ExtractAsync(HashAlgorithmName.SHA512, stream, salt, prk);
```

---

## ⚠️ Error Handling

* `ArgumentException` — for invalid sizes or null contexts.
* `ArgumentOutOfRangeException` — when lengths are outside defined bounds.
* `NotSupportedException` — if unsupported hash algorithm is selected.
* `LibSodiumException` — if the native call fails.

---

## 📝 Notes

* Prefer `DeriveKey()` when simplicity is more important than flexibility.
* Use `Extract`/`Expand` for advanced scenarios: PRK reuse, incremental entropy, or interoperability layers.
* Only `HKDF` supports streaming input for IKM.
* `CryptoKeyDerivation` is deterministic and optimized for fast sequential subkey derivation.
* Using `SecureMemory<byte>` for keys and ikm's is strongly recommended, as it protects key material in unmanaged memory with automatic zeroing and access control.

---

## 👀 See Also

* [libsodium key derivation](https://doc.libsodium.org/key_derivation)
* [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
* [API Reference: CryptoKeyDerivation](../api/LibSodium.CryptoKeyDerivation.yml)
* [API Reference: HKDF](../api/LibSodium.CryptoHkdf.yml)
