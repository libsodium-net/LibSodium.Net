# 🔀 Hashing

LibSodium.Net provides two high-level APIs for hashing:

* `GenericHash` — a flexible cryptographic hash function based on BLAKE2b
* `ShortHash` — a fast keyed hash function based on SipHash-2-4

Both are designed for different purposes:

* Use **GenericHash** for cryptographic hashing tasks such as content integrity, MAC derivation, or generating deterministic fingerprints. It is not suitable for password hashing 
* Use **ShortHash** to protect hash tables against collision-based DoS attacks, using a secret key known only to the application

> 🧂 Based on [libsodium's Hashing](https://doc.libsodium.org/hashing)<br/>
> ℹ️ [API Reference: CryptoGenericHash](../api/LibSodium.CryptoGenericHash.yml)<br/>
> ℹ️ [API Reference: CryptoShortHash](../api/LibSodium.CryptoShortHash.yml)

---

## 🌟 Features

* Cryptographic hashing with variable output length (GenericHash)
* SipHash-based keyed hash for short inputs (ShortHash)
* All methods are allocation-free, Span-based, and deterministic
* Stream and async support for large input hashing (GenericHash)

---

## ✨ GenericHash — BLAKE2b

A secure, cryptographic hash function.

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
CryptoGenericHash.ComputeHash(hash, message, key); // keyed
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

Fast, fixed-size keyed hash designed for short messages. Ideal for protecting hash tables.

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

## ⚠️ Error Handling

* `ArgumentException` — when input or key lengths are invalid
* `LibSodiumException` — if the underlying native function fails

---

## 📝 Notes

* `GenericHash` is based on BLAKE2b and supports variable-length output and optional keys
* `ShortHash` is based on SipHash-2-4 — not a cryptographic hash function, but a keyed primitive appropriate for protecting hash tables against collision-based attacks.
* All hash functions are deterministic: same input and key produce same output
* Use `ShortHash` only when you can keep the key secret

---

## 👀 See Also

* [API Reference: CryptoGenericHash](../api/LibSodium.CryptoGenericHash.yml)
* [API Reference: CryptoShortHash](../api/LibSodium.CryptoShortHash.yml)
* [libsodium.org Hashing](https://doc.libsodium.org/hashing)
