# 🔀 Hashing

LibSodium.Net provides multiple hashing APIs for different use cases:

| API                        | Algorithm    | Use Case                                                                              |
| -------------------------- | ------------ | ------------------------------------------------------------------------------------- |
| `GenericHash`              | BLAKE2b      | Cryptographic hash with optional key. Use for MAC, PRF, fingerprints.                 |
| `ShortHash`                | SipHash‑2‑4  | Keyed hash designed to prevent collisions in hash tables. Fast for short inputs.      |
| `CryptoSha256`             | SHA‑256      | Fast fixed‑length (32‑byte) hash for integrity checks, digital signatures, checksums. |
| `CryptoSha512`             | SHA‑512      | Fast fixed‑length (64‑byte) hash for high‑strength integrity and digital signatures.  |
| `CryptoPasswordHashArgon`  | Argon2id/i13 | Password hashing and key derivation (slow & memory‑hard)                              |
| `CryptoPasswordHashScrypt` | Scrypt       | Password hashing and key derivation (slow & memory‑hard, legacy)                      |

> [!NOTE] 
> 🧂 Based on [libsodium’s Hashing](https://doc.libsodium.org/hashing)<br/>
> 🧂 Based on [Password Hashing](https://doc.libsodium.org/password_hashing)<br/>
> 🧂 Based on [SHA-2](https://doc.libsodium.org/advanced/sha-2_hash_function)<br/>
> ℹ️ [API Reference: CryptoGenericHash](../api/LibSodium.CryptoGenericHash.yml)<br/>
> ℹ️ [API Reference: CryptoShortHash](../api/LibSodium.CryptoShortHash.yml)<br/>
> ℹ️ [API Reference: CryptoPasswordHash](../api/LibSodium.CryptoPasswordHash.yml)<br/>
> ℹ️ [API Reference: CryptoSha256](../api/LibSodium.CryptoSha256.yml)<br/>
> ℹ️ [API Reference: CryptoSha512](../api/LibSodium.CryptoSha512.yml)


---

## 🌟 Features

* Cryptographic hashing with variable output length (GenericHash)
* Fast fixed‑length hashing (CryptoSha256 & CryptoSha512)
* SipHash‑based keyed hash for short inputs (ShortHash)
* Password hashing and key derivation using Argon2 (CryptoPasswordHash)
* All methods are allocation‑free, `Span`‑based, and deterministic (except password hash, which is randomized)
* Stream and async support for large input hashing (GenericHash, CryptoSha256, CryptoSha512)

---

## ✨ GenericHash — BLAKE2b

BLAKE2b is a cryptographic hash function designed as a faster and safer alternative to SHA‑2. It provides high‑performance hashing with optional key support, making it suitable for:

* Cryptographic checksums (fingerprints)
* Message authentication codes (MACs)
* Deriving identifiers or integrity tags
* Hashing files or streams of arbitrary size
* Unique deterministic identifiers
* Pseudorandom functions (PRF) when keyed

By default, it produces 32‑byte output, but can be configured to return between 16 and 64 bytes. It supports *keyed hashing* for MAC‑like behavior, or *unkeyed hashing* for general‑purpose hashing.

### 📏 Constants

| Name         | Value | Description           |
| ------------ | ----- | --------------------- |
| `HashLen`    | 32    | Default output length |
| `MinHashLen` | 16    | Minimum output length |
| `MaxHashLen` | 64    | Maximum output length |
| `KeyLen`     | 32    | Default key length    |
| `MinKeyLen`  | 16    | Minimum key length    |
| `MaxKeyLen`  | 64    | Maximum key length    |

### 📋 Hash with optional key

```csharp
Span<byte> hash = stackalloc byte[CryptoGenericHash.HashLen];
CryptoGenericHash.ComputeHash(hash, message);              // unkeyed
CryptoGenericHash.ComputeHash(hash, message, key);         // keyed (MAC or PRF)
```

### 📋 Hash from a stream

```csharp
using var stream = File.OpenRead("large-input.dat");
CryptoGenericHash.ComputeHash(hash, stream);
```

### 📋 Async stream support

```csharp
using var stream = File.OpenRead("large-input.dat");
await CryptoGenericHash.ComputeHashAsync(hash, stream);
```

---

## ✨ CryptoSha256 — SHA‑256

`CryptoSha256` offers a high‑speed, fixed‑length (32‑byte) SHA‑256 implementation built directly on libsodium’s `crypto_hash_sha256` API. Use it when you need interoperability with existing SHA‑256 digests (e.g., digital signatures, blockchain, TLS certificate fingerprints) or whenever a fixed 32‑byte checksum is required.

### 📏 Constants

| Name      | Value | Description              |
| --------- | ----- | ------------------------ |
| `HashLen` | 32    | Output length (32 bytes) |

### 📋 Hash a byte array

```csharp
Span<byte> hash = stackalloc byte[CryptoSha256.HashLen];
CryptoSha256.ComputeHash(hash, message);
```

### 📋 Hash a stream (buffered, sync)

```csharp
using var stream = File.OpenRead("video.mp4");
CryptoSha256.ComputeHash(hash, stream);
```

### 📋 Async stream hashing

```csharp
await CryptoSha256.ComputeHashAsync(hash, stream);
```

---

## ✨ CryptoSha512 — SHA‑512

`CryptoSha512` is a fixed‑length (64‑byte) implementation of SHA‑512 via libsodium’s `crypto_hash_sha512`. It is usually faster than SHA‑256 on modern 64‑bit CPUs and provides a larger security margin.

### 📏 Constants

| Name      | Value | Description              |
| --------- | ----- | ------------------------ |
| `HashLen` | 64    | Output length (64 bytes) |

### 📋 Hash a byte array

```csharp
Span<byte> hash = stackalloc byte[CryptoSha512.HashLen];
CryptoSha512.ComputeHash(hash, message);
```

### 📋 Hash a stream (buffered, sync)

```csharp
using var stream = File.OpenRead("backup.tar");
CryptoSha512.ComputeHash(hash, stream);
```

### 📋 Async stream hashing

```csharp
await CryptoSha512.ComputeHashAsync(hash, stream);
```

---

## ✨ ShortHash — SipHash‑2‑4

> ⚠️ ShortHash is **not** a cryptographic hash. Do not use it for fingerprinting, content integrity, password hashing, or digital signatures.

SipHash is a fast keyed hash function optimized for short inputs. It is designed to mitigate hash‑flooding attacks in hash tables and similar data structures where untrusted input might lead to performance degradation.

It should be used for:

* Hash table key protection
* Fast authentication of short data
* Use cases where speed and DoS‑resistance are more important than collision resistance

SipHash is always keyed, and its output is always 8 bytes.

### 📏 Constants

| Name      | Value | Description             |
| --------- | ----- | ----------------------- |
| `HashLen` | 8     | Output length (8 bytes) |
| `KeyLen`  | 16    | Key length (16 bytes)   |

### 📋 Hash with key

```csharp
Span<byte> hash = stackalloc byte[CryptoShortHash.HashLen];
CryptoShortHash.ComputeHash(hash, message, key);
```

---

## ✨ PasswordHashArgon

Secure password hashing and key derivation using Argon2 (Argon2id / Argon2i13). This algorithm is specifically designed to defend against brute‑force attacks by requiring significant computational work and memory. It is ideal for storing passwords, deriving keys from passphrases, or implementing authentication mechanisms.

Unlike fast cryptographic hash functions (like SHA‑256 or BLAKE2b), Argon2 is *deliberately slow* and *memory‑intensive*, which drastically increases the cost of large‑scale password cracking (e.g., GPU attacks). LibSodium.Net exposes both Argon2id (recommended) and Argon2i.

The cost parameters (iterations and memory) can be tuned to balance security and performance depending on the context:

* **Interactive** – suitable for login forms.
* **Moderate** – for higher‑value secrets.
* **Sensitive** – for long‑term or critical secrets.

### 📏 Constants

| Name                    | Value          | Description                             |
| ----------------------- | -------------- | --------------------------------------- |
| `SaltLen`               | 16             | Length of the salt in bytes             |
| `MinKeyLen`             | 16             | Minimum key length for derivation       |
| `EncodedLen`            | 128            | Length of the encoded hash string       |
| `Prefix`                | "\$argon2id\$" | Prefix for Argon2id encoded hash        |
| `MinMemoryLen`          | 8 KB           | Minimum acceptable memory for hashing   |
| `MinInterations`        | 1              | Minimum acceptable iterations           |
| `InteractiveIterations` | 2              | Iteration count for interactive targets |
| `InteractiveMemoryLen`  | 64 MB          | Memory usage for interactive targets    |
| `ModerateIterations`    | 3              | For app secrets or backup keys          |
| `ModerateMemoryLen`     | 256Mb          | For app secrets or backup keys          |
| `SensitiveIterations`   | 4              | Iteration count for sensitive targets   |
| `SensitiveMemoryLen`    | 1 GB           | Memory usage for sensitive targets      |


### 📋 Hash a password (encoded, random salt)

```csharp
string hash = CryptoPasswordHash.HashPassword("my password");
```

### 📋 Verify a password

```csharp
bool valid = CryptoPasswordHash.VerifyPassword(hash, "my password");
```

### 📋 Derive a secret key from a password (e.g., for encryption)

```csharp
Span<byte> key = stackalloc byte[32];
Span<byte> salt = stackalloc byte[CryptoPasswordHash.SaltLen];
RandomGenerator.Fill(salt);
CryptoPasswordHash.DeriveKey(key, "password", salt);
```

You can customise the computational cost:

```csharp
CryptoPasswordHash.DeriveKey(
    key, "password", salt,
    iterations: CryptoPasswordHash.SensitiveIterations,
    requiredMemoryLen: CryptoPasswordHash.SensitiveMemoryLen);
```

---

## ✨ PasswordHashScrypt

Password hashing and key derivation using `scrypt`, a memory-hard function introduced before Argon2. Though not side-channel resistant, it is still widely used and interoperable.

LibSodium.Net improves over libsodium by offering consistent tuning options (`Min`, `Interactive`, `Moderate`, `Sensitive`) and full validation coverage.

### 📏 Constants

| Name                    | Value           | Description                         |
| ----------------------- | --------------- | ----------------------------------- |
| `SaltLen`               | 32              | Length of the salt in bytes         |
| `MinKeyLen`             | 16              | Minimum key length for derivation   |
| `EncodedLen`            | 102             | Length of the encoded hash string   |
| `Prefix`                | "\$7\$"         | Prefix for scrypt encoded hash      |
| `MinIterations`         | 1024 (2^10)     | Minimum recommended iterations      |
| `MinMemoryLen`          | 32 KiB (2^15)   | Minimum recommended memory          |
| `InteractiveIterations` | 524288 (2^19)   | For login/password use              |
| `InteractiveMemoryLen`  | 16 MiB (2^24)   | For login/password use              |
| `ModerateIterations`    | 4194304 (2^22)  | For app secrets or backup keys      |
| `ModerateMemoryLen`     | 128 MiB (2^27)  | For app secrets or backup keys      |
| `SensitiveIterations`   | 33554432 (2^25) | For long-term or high-value secrets |
| `SensitiveMemoryLen`    | 1 GiB (2^30)    | For long-term or high-value secrets |

### 📋 Examples

```csharp
string hash = CryptoPasswordHashScrypt.HashPassword("my password");
bool valid = CryptoPasswordHashScrypt.VerifyPassword(hash, "my password");
```

```csharp
Span<byte> key = stackalloc byte[32];
Span<byte> salt = stackalloc byte[CryptoPasswordHashScrypt.SaltLen];
RandomGenerator.Fill(salt);
CryptoPasswordHashScrypt.DeriveKey(key, "password", salt,
    iterations: CryptoPasswordHashScrypt.ModerateIterations,
    requiredMemoryLen: CryptoPasswordHashScrypt.ModerateMemoryLen);
```

---

## ⚠️ Error Handling

* `ArgumentException` — when input or key lengths are invalid
* `ArgumentOutOfRangeException` — when iterations or memory limits are too low
* `LibSodiumException` — if the underlying native function fails

---

## 📝 Notes

* `GenericHash` is based on BLAKE2b and supports variable‑length output and optional keys.
* `CryptoSha256` and `CryptoSha512` provide interoperable SHA‑2 digests and are the best choice when you need a *fixed‑length* checksum or compatibility with external systems.
* `ShortHash` is based on SipHash‑2‑4 — *not* a general‑purpose cryptographic hash, but a keyed primitive for protecting hash tables.
* `CryptoPasswordHashArgon` uses Argon2id/Argon2i13 with computational and memory hardness.
* All hash functions are deterministic: same input and key produce same output — **except** `CryptoPasswordHash.HashPassword`, which includes a random salt and produces a different hash each time.
* `Scrypt` is **not side-channel resistant**. Use `Argon2i13` or `Argon2id13` for high-security or shared-host scenarios.
* Use `ShortHash` only when you can keep the key secret.

---

## 🧭 Choosing the Right Hash API

| Scenario                                                 | Recommended API            |
| -------------------------------------------------------- | -------------------------- |
| Variable‑length cryptographic checksum                   | `GenericHash`              |
| Fixed‑length 32‑byte digest (e.g., TLS cert fingerprint) | `CryptoSha256`             |
| Fixed‑length 64‑byte digest, higher speed on x64         | `CryptoSha512`             |
| MAC or PRF                                               | `GenericHash` (keyed)      |
| Hashing short keys in tables                             | `ShortHash`                |
| Password storage / passphrase‑derived keys               | `CryptoPasswordHashArgon`  |
| Legacy Password storage / passphrase‑derived keys        | `CryptoPasswordHashScrypt` |

## 👀 See Also

* ℹ️ [API Reference: CryptoGenericHashArgon](../api/LibSodium.CryptoGenericHashArgon.yml)
* ℹ️ [API Reference: CryptoGenericHashArgon](../api/LibSodium.CryptoGenericHashScrypt.yml)
* ℹ️ [API Reference: CryptoSha256](../api/LibSodium.CryptoSha256.yml)
* ℹ️ [API Reference: CryptoSha512](../api/LibSodium.CryptoSha512.yml)
* ℹ️ [API Reference: CryptoShortHash](../api/LibSodium.CryptoShortHash.yml)
* ℹ️ [API Reference: CryptoPasswordHash](../api/LibSodium.CryptoPasswordHash.yml)
* 🧂 [libsodium Hashing](https://doc.libsodium.org/hashing)
* 🧂 [libsodium Password Hashing](https://doc.libsodium.org/password_hashing)
* 🧂 [libsodium SHA-2](https://doc.libsodium.org/advanced/sha-2_hash_function)<br/>
