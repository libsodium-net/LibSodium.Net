# 🔀 Hashing

LibSodium.Net provides multiple hashing APIs for different use cases:

| API                  | Algorithm    | Use Case                                                                         |
| -------------------- | ------------ | -------------------------------------------------------------------------------- |
| `GenericHash`        | BLAKE2b      | Cryptographic hash with optional key. Use for MAC, PRF, fingerprints.            |
| `ShortHash`          | SipHash-2-4  | Keyed hash designed to prevent collisions in hash tables. Fast for short inputs. |
| `CryptoPasswordHash` | Argon2id/i13 | Password hashing and key derivation (slow & memory hard)                         |

> 🧂 Based on [libsodium's Hashing](https://doc.libsodium.org/hashing) and [Password Hashing](https://doc.libsodium.org/password_hashing)<br/>
> ℹ️ [API Reference: CryptoGenericHash](../api/LibSodium.CryptoGenericHash.yml)<br/>
> ℹ️ [API Reference: CryptoShortHash](../api/LibSodium.CryptoShortHash.yml)<br/>
> ℹ️ [API Reference: CryptoPasswordHash](../api/LibSodium.CryptoPasswordHash.yml)

---

## 🌟 Features

* Cryptographic hashing with variable output length (GenericHash)
* SipHash-based keyed hash for short inputs (ShortHash)
* Password hashing and key derivation using Argon2 (CryptoPasswordHash)
* All methods are allocation-free, Span-based, and deterministic (except password hash, which is randomized)
* Stream and async support for large input hashing (GenericHash)

---

## ✨ GenericHash — BLAKE2b

BLAKE2b is a cryptographic hash function designed as a faster and safer alternative to SHA-2. It provides high-performance hashing with optional key support, making it suitable for:

* Cryptographic checksums (fingerprints)
* Message authentication codes (MACs)
* Deriving identifiers or integrity tags
* Hashing files or streams of arbitrary size
* Unique deterministic identifiers
* Pseudorandom functions (PRF) when keyed

By default, it produces 32-byte output, but can be configured to return between 16 and 64 bytes. It supports *keyed hashing* for MAC-like behavior, or *unkeyed hashing* for general-purpose hashing.

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
CryptoGenericHash.ComputeHash(hash, message); // unkeyed
CryptoGenericHash.ComputeHash(hash, message, key); // keyed (MAC or PRF)
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

## ✨ ShortHash — SipHash-2-4

> ⚠️ ShortHash is not a cryptographic hash. Do not use it for fingerprinting, content integrity, password hashing, or digital signatures.

SipHash is a fast keyed hash function optimized for short inputs. It is designed to mitigate hash-flooding attacks in hash tables and similar data structures where untrusted input might lead to performance degradation. 

It should be used for:

* Hash table key protection
* Fast authentication of short data
* Use cases where speed and DoS-resistance are more important than collision resistance

SipHash is always keyed, and its output is always 8 bytes.

### 📏 Constants

| Name      | Value | Description             |
| --------- | ----- | ----------------------- |
| `HashLen` | 8     | Output length (8 bytes) |
| `KeyLen`  | 16    | Key length (16 bytes)   |

### 📋 Hash with key

```csharp
Span<byte> hash = stackalloc byte[CryptoShortHash.HashLen];
CryptoShortHash.ComputeHash(hash, message, key);
```

---

## ✨ PasswordHash — Argon2id / Argon2i13

Secure password hashing and key derivation using Argon2. This algorithm is specifically designed to defend against brute-force attacks by requiring significant computational work and memory. It is ideal for storing passwords, deriving keys from passphrases, or implementing authentication mechanisms.

Unlike fast cryptographic hash functions (like SHA-256 or BLAKE2b), Argon2 is *deliberately slow* and *memory-intensive*, which drastically increases the cost of large-scale password cracking (e.g., GPU attacks). LibSodium.Net exposes both Argon2id (recommended) and Argon2i.

The cost parameters (iterations and memory) can be tuned to balance security and performance depending on the context:

* **Interactive**: suitable for login forms.
* **Moderate**: for higher value secrets.
* **Sensitive**: for long-term or critical secrets.

### 📏 Constants

| Name                    | Value          | Description                             |
| ----------------------- | -------------- | --------------------------------------- |
| `SaltLen`               | 16             | Length of the salt in bytes             |
| `MinKeyLen`             | 16             | Minimum key length for derivation       |
| `EncodedLen`            | 128            | Length of the encoded hash string       |
| `Prefix`                | "\$argon2id\$" | Prefix for Argon2id encoded hash        |
| `InteractiveIterations` | 2              | Iteration count for interactive targets |
| `InteractiveMemoryLen`  | 64 MB          | Memory usage for interactive targets    |
| `SensitiveIterations`   | 4              | Iteration count for sensitive targets   |
| `SensitiveMemoryLen`    | 1 GB           | Memory usage for sensitive targets      |
| `MinMemoryLen`          | 8 KB           | Minimum acceptable memory for hashing   |

### 📋 Hash a password (encoded, random salt)

```csharp
string hash = CryptoPasswordHash.HashPassword("my password");
```

### 📋 Verify a password

```csharp
bool valid = CryptoPasswordHash.VerifyPassword(hash, "my password");
```

### 📋 Derive a secret key from a password (e.g. for encryption)

```csharp
Span<byte> key = stackalloc byte[32];
Span<byte> salt = stackalloc byte[CryptoPasswordHash.SaltLen];
RandomGenerator.Fill(salt);
CryptoPasswordHash.DeriveKey(key, "password", salt);
```

You can customize the computational cost:

```csharp
CryptoPasswordHash.DeriveKey(
    key, "password", salt,
    iterations: CryptoPasswordHash.SensitiveIterations,
    requiredMemoryLen: CryptoPasswordHash.SensitiveMemoryLen);
```

---

## ⚠️ Error Handling

* `ArgumentException` — when input or key lengths are invalid
* `ArgumentOutOfRangeException` — when iterations or memory limits are too low
* `LibSodiumException` — if the underlying native function fails

---

## 📝 Notes

* `GenericHash` is based on BLAKE2b and supports variable-length output and optional keys. It is suitable for both fingerprinting, MACs, PRFs, and unique identifier generation.
* `ShortHash` is based on SipHash-2-4 — not a cryptographic hash function, but a keyed primitive appropriate for protecting hash tables against collision-based attacks.
* `CryptoPasswordHash` uses Argon2id/Argon2i13, with computational and memory hardness
* All hash functions are deterministic: same input and key produce same output — **except** for `CryptoPasswordHash.HashPassword`, which includes a random salt and produces a different hash each time.
* Use `ShortHash` only when you can keep the key secret

---

## 🧭 Choosing the Right Hash API

| Scenario                         | Recommended API         |
| -------------------------------- | ----------------------- |
| Content integrity (files, blobs) | `GenericHash` (unkeyed) |
| MAC or PRF                       | `GenericHash` (keyed)   |
| Hashing short keys in tables     | `ShortHash`             |
| Password storage                 | `CryptoPasswordHash`    |
| Key derivation from passphrase   | `CryptoPasswordHash`    |

## 👀 See Also

* [API Reference: CryptoGenericHash](../api/LibSodium.CryptoGenericHash.yml)
* [API Reference: CryptoShortHash](../api/LibSodium.CryptoShortHash.yml)
* [API Reference: CryptoPasswordHash](../api/LibSodium.CryptoPasswordHash.yml)
* [libsodium.org Hashing](https://doc.libsodium.org/hashing)
* [libsodium Password Hashing](https://doc.libsodium.org/password_hashing)
