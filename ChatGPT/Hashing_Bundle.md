# 🧩 LibSodium.Net Hashing Bundle

This bundle contains the full source, tests, and guide for:

- `CryptoGenericHash` (BLAKE2b)
- `CryptoShortHash` (SipHash-2-4)
- `CryptoPasswordHash` (Argon2id/i13)
- `CryptoSha256`
- `CryptoSha512`
- ✅ With complete test coverage and guide

---

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


> 🧂 Based on [libsodium’s Hashing](https://doc.libsodium.org/hashing)<br/>
> 🧂 Based on [Password Hashing](https://doc.libsodium.org/password_hashing)<br/>
> 🧂 Based on [SHA-2](https://doc.libsodium.org/advanced/sha-2_hash_function)<br/>
> ℹ️ [API Reference: CryptoGenericHash](../api/LibSodium.CryptoGenericHash.yml)<br/>
> ℹ️ [API Reference: CryptoSha256](../api/LibSodium.CryptoSha256.yml)<br/>
> ℹ️ [API Reference: CryptoSha512](../api/LibSodium.CryptoSha512.yml)
> ℹ️ [API Reference: CryptoShortHash](../api/LibSodium.CryptoShortHash.yml)<br/>
> ℹ️ [API Reference: CryptoPasswordHashArgon](../api/LibSodium.CryptoPasswordHashArgon.yml)<br/>
> ℹ️ [API Reference: CryptoPasswordHashScrypt](../api/LibSodium.CryptoPasswordHashScrypt.yml)<br/>



---

## 🌟 Features

* Cryptographic hashing with variable output length (GenericHash)
* Fast fixed‑length hashing (CryptoSha256 & CryptoSha512)
* SipHash‑based keyed hash for short inputs (ShortHash)
* Password hashing and key derivation using Argon2 (CryptoPasswordHash)
* All methods are allocation‑free, `Span`‑based, and deterministic (except password hash, which is randomized)
* Stream and async support for large input hashing (GenericHash, CryptoSha256, CryptoSha512)
* Incremental (multi-part) hashing  (GenericHash, CryptoSha256, CryptoSha512)

---

## ✨ GenericHash — BLAKE2b

BLAKE2b is a cryptographic hash function designed as a faster and safer alternative to SHA‑2. It provides high‑performance hashing with optional key support, making it suitable for:

* Cryptographic checksums (fingerprints)
* Message authentication codes (MACs)
* Deriving identifiers or integrity tags
* Hashing files or streams of arbitrary size
* Unique deterministic identifiers
* Pseudorandom functions (PRF) when keyed

By default, it produces 32‑byte output, but can be configured to return between 16 and 64 bytes. It supports *keyed hashing* for MAC‑like or PRF behavior, using a key of 32 bytes by default (configurable between 16 and 64 bytes), or *unkeyed hashing* for general‑purpose use.

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
## ✨ Incremental Hashing

In some scenarios, data to be hashed is not available as a single contiguous buffer — for example, when you want to compute `hash(a || b || c)` from multiple inputs. LibSodium.Net offers **incremental hashing** for this purpose.

The following classes support incremental hashing:

* `CryptoGenericHash` (BLAKE2b, optionally keyed)
* `CryptoSha256` (SHA-256)
* `CryptoSha512` (SHA-512)

These types expose an incremental API via the `ICryptoIncrementalHash` interface.

### 📋 Compute hash from multiple parts

```csharp
Span<byte> hash = stackalloc byte[CryptoSha256.HashLen];
using var hasher = CryptoSha256.CreateIncrementalHash();

hasher.Update(Encoding.UTF8.GetBytes("header"));
hasher.Update(Encoding.UTF8.GetBytes("payload"));
hasher.Update(Encoding.UTF8.GetBytes("footer"));
hasher.Final(hash);
```

This pattern ensures correctness and efficiency when you want to hash logically grouped inputs without allocating or copying them into a single buffer.

### 📋 With a keyed BLAKE2b hash

```csharp
Span<byte> key = stackalloc byte[CryptoGenericHash.KeyLen];
RandomGenerator.Fill(key);

Span<byte> hash = stackalloc byte[32];
var part1 = Encoding.UTF8.GetBytes("hello");
var part2 = Encoding.UTF8.GetBytes("world");

using var hasher = CryptoGenericHash.CreateIncrementalHash(key, hash.Length);

hasher.Update(part1);
hasher.Update(part2);
hasher.Final(hash);
```

> ℹ️ The `Final()` method may only be called once per hash instance. You must create a new instance for each new computation.

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

* ℹ️ [API Reference: CryptoGenericHash](../api/LibSodium.CryptoGenericHash.yml)
* ℹ️ [API Reference: CryptoSha256](../api/LibSodium.CryptoSha256.yml)
* ℹ️ [API Reference: CryptoSha512](../api/LibSodium.CryptoSha512.yml)
* ℹ️ [API Reference: CryptoShortHash](../api/LibSodium.CryptoShortHash.yml)
* ℹ️ [API Reference: CryptoPasswordHashArgon](../api/LibSodium.CryptoPasswordHashArgon.yml)
* ℹ️ [API Reference: CryptoPasswordHashScrypt](../api/LibSodium.CryptoPasswordHashScrypt.yml)
* 🧂 [libsodium Hashing](https://doc.libsodium.org/hashing)
* 🧂 [libsodium Password Hashing](https://doc.libsodium.org/password_hashing)
* 🧂 [libsodium SHA-2](https://doc.libsodium.org/advanced/sha-2_hash_function)<br/>


---

## 📦 Source: CryptoGenericHash.cs
```csharp
using LibSodium.Interop;
using System.Buffers;
using System.Security.Cryptography;

namespace LibSodium
{
	/// <summary>
	/// Provides a high-level interface to the libsodium generic hash function, based on BLAKE2b.
	/// </summary>
	/// <remarks>
	/// This class wraps the <c>crypto_generichash</c> functions from libsodium, offering both one-shot and streaming hash computations.
	/// The output length and key length can be customized within defined bounds. The hash can be computed over a byte span or a stream,
	/// synchronously or asynchronously.
	/// <para>
	/// For additional details, see the official libsodium documentation: 🧂
	/// https://libsodium.gitbook.io/doc/hashing/generic_hashing
	/// </para>
	/// </remarks>
	public static class CryptoGenericHash
	{
		private const int DefaultBufferSize = 8192; // Default buffer size for stream operations


		/// <summary>
		/// Default hash length in bytes (32).
		/// </summary>
		public const int HashLen = Native.CRYPTO_GENERICHASH_BYTES;
		/// <summary>
		/// Minimum allowed length in bytes for the hash (16).
		/// </summary>
		public const int MinHashLen = Native.CRYPTO_GENERICHASH_BYTES_MIN;
		/// <summary>
		/// Maximum allowed length in bytes for the hash (64).
		/// </summary>
		public const int MaxHashLen = Native.CRYPTO_GENERICHASH_BYTES_MAX;
		/// <summary>
		/// Default key length in bytes (32).
		/// </summary>
		public const int KeyLen = Native.CRYPTO_GENERICHASH_KEYBYTES;
		/// <summary>
		/// Minimum length in bytes for secret keys (16).
		/// </summary>
		public const int MinKeyLen = Native.CRYPTO_GENERICHASH_KEYBYTES_MIN;
		/// <summary>
		/// Maximum allowed key length in bytes (64 bytes).
		/// </summary>
		public const int MaxKeyLen = Native.CRYPTO_GENERICHASH_KEYBYTES_MAX;

		internal static readonly int StateLen = (int) Native.crypto_generichash_statebytes();

		/// <summary>
		/// Computes a generic hash of the specified message.
		/// </summary>
		/// <param name="hash">The buffer where the computed hash will be written. Its length defines the output size.</param>
		/// <param name="message">The input message to hash.</param>
		/// <param name="key">An optional key for keyed hashing (HMAC-like). May be empty for unkeyed mode.</param>
		/// <exception cref="ArgumentException">
		/// Thrown if <paramref name="hash"/> has an invalid length, or if <paramref name="key"/> is too long.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the hashing operation fails internally.</exception>

		public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key = default)
		{
			if (hash.Length < MinHashLen || hash.Length > MaxHashLen)
			{
				throw new ArgumentException($"Hash length must be between {MinHashLen} and {MaxHashLen} bytes.", nameof(hash));
			}
			if (key.Length != 0 && (key.Length < MinKeyLen || key.Length > MaxKeyLen))
			{
				throw new ArgumentOutOfRangeException($"Key length must be between {MinKeyLen} and {MaxKeyLen} bytes.", nameof(key));
			}
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_generichash(hash, (nuint)hash.Length, message, (ulong)message.Length, key, (nuint)key.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");
		}


		/// <summary>
		/// Computes a generic hash from the contents of a stream.
		/// </summary>
		/// <param name="hash">The buffer where the computed hash will be written. Its length defines the output size.</param>
		/// <param name="input">The input stream to read and hash.</param>
		/// <param name="key">An optional key for keyed hashing (HMAC-like). May be empty for unkeyed mode.</param>
		/// <exception cref="ArgumentException">
		/// Thrown if <paramref name="hash"/> has an invalid length, or if <paramref name="key"/> is too long.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the hashing operation fails internally.</exception>

		public static void ComputeHash(Span<byte> hash, Stream input, ReadOnlySpan<byte> key = default)
		{
			ArgumentNullException.ThrowIfNull(input, nameof(input));

			using (var incrementalHash = CreateIncrementalHash(key, hash.Length))
			{
				incrementalHash.Compute(input, hash);
			}
		}

		/// <summary>
		/// Asynchronously computes a generic hash from the contents of a stream.
		/// </summary>
		/// <param name="hash">The memory buffer where the computed hash will be written. Its length defines the output size.</param>
		/// <param name="input">The input stream to read and hash.</param>
		/// <param name="key">An optional key for keyed hashing (HMAC-like). May be empty for unkeyed mode.</param>
		/// <param name="cancellationToken">A cancellation token to cancel the operation.</param>
		/// <returns>A task representing the asynchronous hash computation.</returns>
		/// <exception cref="ArgumentException">
		/// Thrown if <paramref name="hash"/> has an invalid length, or if <paramref name="key"/> is too long.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the hashing operation fails internally.</exception>

		public static async Task ComputeHashAsync(Memory<byte> hash, Stream input, ReadOnlyMemory<byte> key = default, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(input, nameof(input));

			using (var incrementalHash = CreateIncrementalHash(key.Span, hash.Length))
			{
				await incrementalHash.ComputeAsync(input, hash, cancellationToken).ConfigureAwait(false);
			}
		}

		public static ICryptoIncrementalHash CreateIncrementalHash(ReadOnlySpan<byte> key = default, int hashLen = HashLen)
		{
			return new CryptoGenericHashIncremental(key, hashLen);
		}

	}
}

```
---
## 📦 Source: CryptoGenericHashIncremental.cs

```csharp
using LibSodium.Interop;
using System.Runtime.InteropServices;

namespace LibSodium
{
	internal sealed class CryptoGenericHashIncremental : ICryptoIncrementalHash
	{
		private  Native.crypto_generichash_blake2b_state state;
		private bool isDisposed = false;
		private bool isFinalized = false;
		private readonly int hashLen;

		public CryptoGenericHashIncremental(ReadOnlySpan<byte> key, int hashLen)
		{
			this.hashLen = hashLen;
			if (key.Length != 0 && (key.Length < CryptoGenericHash.MinKeyLen || key.Length > CryptoGenericHash.MaxKeyLen))
			{
				throw new ArgumentOutOfRangeException($"Key length must be between {CryptoGenericHash.MinKeyLen} and {CryptoGenericHash.MaxKeyLen} bytes.", nameof(key));
			}
			if (hashLen < CryptoGenericHash.MinHashLen || hashLen > CryptoGenericHash.MaxHashLen)
			{
				throw new ArgumentException($"Hash length must be between {CryptoGenericHash.MinHashLen} and {CryptoGenericHash.MaxHashLen} bytes.", nameof(hashLen));
			}
			if (Native.crypto_generichash_init(ref state, key, (nuint) key.Length, (nuint) hashLen) != 0)
			{
				throw new LibSodiumException("Failed to initialize incremental hashing.");
			}
		}

		private void CheckDisposed()
		{
			if (isDisposed)
			{
				throw new ObjectDisposedException(nameof(CryptoGenericHashIncremental), "The incremental hash has already been disposed.");
			}
		}

		public void Update(ReadOnlySpan<byte> data)
		{
			CheckDisposed();
			if (isFinalized)
			{
				throw new InvalidOperationException("Cannot update a finalized hash");
			}
			int result = Native.crypto_generichash_update(ref state, data, (ulong)data.Length);
			if (result != 0)
				throw new LibSodiumException("Failed to update the incremental hashing operation.");
		}

		public void Final(Span<byte> hash)
		{
			CheckDisposed();
			if (isFinalized)
			{
				throw new InvalidOperationException("Hash has already been finalized.");
			}
			if (hash.Length != hashLen)
			{
				throw new ArgumentException($"Hash must be exactly {hashLen} bytes, matching the hash length specified at construction.", nameof(hash));
			}
			int result = Native.crypto_generichash_final(ref state, hash, (nuint)hashLen);
			if (result != 0)
			{
				throw new LibSodiumException("Failed to finalize the incremental hashing operation.");
			}
			SecureMemory.MemZero(ref state); // Clear the state to prevent sensitive data leakage
			isFinalized = true;
		}

		public void Dispose()
		{
			if (isDisposed) return;
			isDisposed = true;
			if (!isFinalized)
			{
				SecureMemory.MemZero(ref state); // Clear the state to prevent sensitive data leakage
			}
		}
	}
}

```

---

## 📦 Source: CryptoShortHash.cs

```csharp

using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides a high-level interface to the libsodium short-input hash function, based on SipHash-2-4.
	/// </summary>
	/// <remarks>
	/// This function is optimized for short messages and uses a 16-byte secret key to protect against hash-flooding
	/// attacks. It is not suitable for general-purpose cryptographic hashing.
	/// <para>
	/// 🧂 https://libsodium.gitbook.io/doc/hashing/short-input_hashing
	/// </para>
	/// </remarks>
	public static class CryptoShortHash
    {
        /// <summary>
        /// Hash length in bytes (8).
        /// </summary>
        public const int HashLen = Native.CRYPTO_SHORTHASH_BYTES;

        /// <summary>
        /// Key length in bytes (16).
        /// </summary>
        public const int KeyLen = Native.CRYPTO_SHORTHASH_KEYBYTES;

		/// <summary>
		/// Computes a short hash (SipHash-2-4) of the given message using the provided 16-byte key. The key must remain secret. 
		/// This function will not provide any mitigations against DoS attacks if the key is known from attackers.
		/// </summary>
		/// <param name="hash">A buffer of exactly 8 bytes to receive the output.</param>
		/// <param name="message">The message to hash.</param>
		/// <param name="key">A 16-byte secret key.</param>
		/// <exception cref="ArgumentException">Thrown if the key or hash buffer is not of expected length.</exception>
		/// <exception cref="LibSodiumException">Thrown if the hashing operation fails.</exception>
		public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
        {
            if (hash.Length != HashLen)
                throw new ArgumentException($"Hash length must be exactly {HashLen} bytes.", nameof(hash));
            if (key.Length != KeyLen)
                throw new ArgumentException($"Key length must be exactly {KeyLen} bytes.", nameof(key));

            LibraryInitializer.EnsureInitialized();

            int result = Native.crypto_shorthash(hash, message, (ulong)message.Length, key);
            if (result != 0)
                throw new LibSodiumException("Short hash computation failed.");
        }
    }
}
```

---

## 📦 Source: CryptoPasswordHash.cs

```csharp
using LibSodium.Interop;
using System.Text;

namespace LibSodium
{
    /// <summary>
    /// Supported password hashing algorithms.
    /// </summary>
    public enum PasswordHashAlgorithm
    {
        /// <summary>
        /// Argon2i version 1.3 — optimized for side-channel resistance.
        /// </summary>
        Argon2i13 = Native.CRYPTO_PWHASH_ALG_ARGON2I13,

        /// <summary>
        /// Argon2id version 1.3 — hybrid mode (default and recommended).
        /// </summary>
        Argon2id13 = Native.CRYPTO_PWHASH_ALG_ARGON2ID13
    }

    /// <summary>
    /// Provides password hashing and key derivation using Argon2.
    /// </summary>
    /// <remarks>
    /// 🧂 Based on libsodium's crypto_pwhash API: https://doc.libsodium.org/password_hashing
    /// </remarks>
    public static class CryptoPasswordHash
    {
		/// <summary>
		/// Minimum allowed length in bytes for the derived key (16).
		/// </summary>
		public const int MinKeyLen = Native.CRYPTO_PWHASH_BYTES_MIN;

		/// <summary>
		/// Minimum allowed password length in bytes (0).
		/// </summary>
		public const int MinPasswordLen = Native.CRYPTO_PWHASH_PASSWD_MIN;

		/// <summary>
		/// Length of the salt in bytes (16).
		/// </summary>
		public const int SaltLen = Native.CRYPTO_PWHASH_SALTBYTES;

		/// <summary>
		/// Maximum length of the encoded hash string (includes null terminator) (128).
		/// </summary>
		public const int EncodedLen = Native.CRYPTO_PWHASH_STRBYTES;

		/// <summary>
		/// Minimum number of iterations for key derivation (1).
		/// </summary>
		public const int MinIterations = Native.CRYPTO_PWHASH_OPSLIMIT_MIN;

		/// <summary>
		/// Recommended iterations for interactive use (2).
		/// </summary>
		public const int InteractiveIterations = Native.CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;

		/// <summary>
		/// Recommended iterations for moderate use (3).
		/// </summary>
		public const int ModerateIterations = Native.CRYPTO_PWHASH_OPSLIMIT_MODERATE;

		/// <summary>
		/// Recommended iterations for sensitive use (4).
		/// </summary>
		public const int SensitiveIterations = Native.CRYPTO_PWHASH_OPSLIMIT_SENSITIVE;

		/// <summary>
		/// Minimum memory usage in bytes (8k).
		/// </summary>
		public const int MinMemoryLen = Native.CRYPTO_PWHASH_MEMLIMIT_MIN;

		/// <summary>
		/// Recommended memory usage for interactive use (64Mb).
		/// </summary>
		public const int InteractiveMemoryLen = Native.CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;

		/// <summary>
		/// Recommended memory usage for moderate use (256Mb).
		/// </summary>
		public const int ModerateMemoryLen = Native.CRYPTO_PWHASH_MEMLIMIT_MODERATE;

		/// <summary>
		/// Recommended memory usage for sensitive use (1Gb).
		/// </summary>
		public const int SensitiveMemoryLen = Native.CRYPTO_PWHASH_MEMLIMIT_SENSITIVE;

		/// <summary>
		/// Prefix for the encoded hash string (e.g. "$argon2id$").
		/// </summary>
		public const string Prefix = Native.CRYPTO_PWHASH_STRPREFIX;



		/// <summary>
		/// Derives a secret key from a password and salt using Argon2.
		/// </summary>
		/// <param name="key">Buffer to receive the derived key (recommended: 32 bytes).</param>
		/// <param name="password">The password to hash.</param>
		/// <param name="salt">The salt (must be 16 bytes).</param>
		/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
		/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
		/// <param name="algorithm">Hash algorithm to use (default: Argon2id13).</param>
		/// <exception cref="ArgumentException">If arguments are invalid.</exception>
		/// <exception cref="LibSodiumException">If hashing fails.</exception>
		public static void DeriveKey(
            Span<byte> key,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            int iterations = InteractiveIterations,
            int requiredMemoryLen = InteractiveMemoryLen,
            PasswordHashAlgorithm algorithm = PasswordHashAlgorithm.Argon2id13)
        {
			if (key.Length < MinKeyLen)
				throw new ArgumentOutOfRangeException($"Key length must be at least {MinKeyLen} bytes.", nameof(key));

			if (password.Length < MinPasswordLen)
				throw new ArgumentOutOfRangeException($"Password length must be at least {MinPasswordLen} bytes.", nameof(password));

			if (salt.Length != SaltLen)
				throw new ArgumentException($"Salt must be exactly {SaltLen} bytes.", nameof(salt));

			if (iterations < MinIterations)
				throw new ArgumentOutOfRangeException(nameof(iterations), $"Iterations must be at least {MinIterations}.");

			if (requiredMemoryLen < MinMemoryLen)
				throw new ArgumentOutOfRangeException(nameof(requiredMemoryLen), $"Memory length must be at least {MinMemoryLen} bytes.");

			if (algorithm == PasswordHashAlgorithm.Argon2i13 && iterations < 3)
				throw new ArgumentOutOfRangeException(nameof(iterations), "Argon2i13 requires iterations >= 3 for side-channel resistance.");

			LibraryInitializer.EnsureInitialized();

            int result = Native.crypto_pwhash(
                key, (ulong)key.Length,
                password, (ulong)password.Length,
                salt,
                (ulong)iterations, (nuint)requiredMemoryLen, (int)algorithm);

            if (result != 0)
                throw new LibSodiumException("DeriveKey failed. Possible out of memory.");
        }

		/// <summary>
		/// Derives a secret key from a password string and salt using Argon2.
		/// </summary>
		/// <param name="key">Buffer to receive the derived key (recommended: 32 bytes).</param>
		/// <param name="password">The password string to hash.</param>
		/// <param name="salt">The salt (must be 16 bytes).</param>
		/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
		/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
		/// <param name="algorithm">Hash algorithm to use (default: Argon2id13).</param>
		/// <exception cref="ArgumentNullException">If the password is null.</exception>
		/// <exception cref="LibSodiumException">If hashing fails.</exception>
		public static void DeriveKey(
			Span<byte> key,
			string password,
			ReadOnlySpan<byte> salt,
			int iterations = InteractiveIterations,
			int requiredMemoryLen = InteractiveMemoryLen,
			PasswordHashAlgorithm algorithm = PasswordHashAlgorithm.Argon2id13)
		{
			ArgumentNullException.ThrowIfNull(password);

			var passwordUtf8Len = Encoding.UTF8.GetByteCount(password);

			Span<byte> passwordUtf8 = passwordUtf8Len > Constants.MaxStackAlloc ? new byte[passwordUtf8Len]:  stackalloc byte[passwordUtf8Len];
			Encoding.UTF8.GetBytes(password, passwordUtf8);

			DeriveKey(key, passwordUtf8, salt, iterations, requiredMemoryLen, algorithm);
		}

		/// <summary>
		/// Hashes a password into a human-readable string (including algorithm and parameters).
		/// </summary>
		/// <param name="password">The password to hash (in UTF-8).</param>
		/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
		/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
		/// <returns>A string containing only ASCII characters, including the algorithm identifier, salt, and parameters.</returns>
		/// <exception cref="ArgumentOutOfRangeException">If password is too short or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">If hashing fails.</exception>
		public static string HashPassword(
			ReadOnlySpan<byte> password,
			int iterations = InteractiveIterations,
			int requiredMemoryLen = InteractiveMemoryLen)
		{
			if (password.Length < MinPasswordLen)
				throw new ArgumentOutOfRangeException($"Password length must be at least {MinPasswordLen} bytes.", nameof(password));

			if (iterations < MinIterations)
				throw new ArgumentOutOfRangeException(nameof(iterations), $"Iterations must be at least {MinIterations}.");

			if (requiredMemoryLen < MinMemoryLen)
				throw new ArgumentOutOfRangeException(nameof(requiredMemoryLen), $"Memory length must be at least {MinMemoryLen} bytes.");

			Span<byte> buffer = stackalloc byte[EncodedLen];
			int result = Native.crypto_pwhash_str(
				buffer,
				password, (ulong)password.Length,
				(ulong)iterations, (nuint)requiredMemoryLen);

			if (result != 0)
				throw new LibSodiumException("HashPassword failed. Possible out of memory.");

			return Encoding.ASCII.GetString(buffer.Slice(0, buffer.IndexOf((byte)0)));
		}

		/// <summary>
		/// Hashes a password string into a human-readable string (including algorithm and parameters).
		/// </summary>
		/// <param name="password">The password to hash (as string).</param>
		/// <param name="iterations">Computation cost (default: INTERACTIVE).</param>
		/// <param name="requiredMemoryLen">Memory usage limit in bytes (default: INTERACTIVE).</param>
		/// <returns>A string containing only ASCII characters, including the algorithm identifier, salt, and parameters.</returns>
		/// <exception cref="ArgumentNullException">If the password is null.</exception>
		/// <exception cref="ArgumentOutOfRangeException">If parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">If hashing fails.</exception>
		public static string HashPassword(
			string password,
			int iterations = InteractiveIterations,
			int requiredMemoryLen = InteractiveMemoryLen)
		{
			ArgumentNullException.ThrowIfNull(password);

			var passwordUtf8Len = Encoding.UTF8.GetByteCount(password);
			Span<byte> passwordUtf8 = passwordUtf8Len > Constants.MaxStackAlloc ? new byte[passwordUtf8Len] : stackalloc byte[passwordUtf8Len];
			Encoding.UTF8.GetBytes(password, passwordUtf8);

			return HashPassword(passwordUtf8, iterations, requiredMemoryLen);
		}

		/// <summary>
		/// Verifies a password against a previously hashed string.
		/// </summary>
		/// <param name="hashedPassword">The encoded password hash string (must be ASCII and null-terminated).</param>
		/// <param name="password">The password to verify.</param>
		/// <returns><c>true</c> if the password is valid; otherwise, <c>false</c>.</returns>
		/// <exception cref="ArgumentNullException">If <paramref name="hashedPassword"/> is null.</exception>
		/// <exception cref="ArgumentException">If <paramref name="hashedPassword"/> is too long.</exception>
		public static bool VerifyPassword(
			string hashedPassword,
			ReadOnlySpan<byte> password)
		{
			ArgumentNullException.ThrowIfNull(hashedPassword);

			Span<byte> buffer = stackalloc byte[EncodedLen];
			if (Encoding.ASCII.GetBytes(hashedPassword, buffer) >= EncodedLen)
			{
				throw new ArgumentException($"Hashed password is too long. Max allowed length is {EncodedLen - 1} characters.", nameof(hashedPassword));
			};

			int result = Native.crypto_pwhash_str_verify(
				buffer,
				password, (ulong)password.Length);

			return result == 0;
		}

		/// <summary>
		/// Verifies a password string against a previously hashed string.
		/// </summary>
		/// <param name="hashedPassword">The encoded password hash string (must be ASCII and null-terminated).</param>
		/// <param name="password">The password to verify (as string).</param>
		/// <returns><c>true</c> if the password is valid; otherwise, <c>false</c>.</returns>
		/// <exception cref="ArgumentNullException">If <paramref name="password"/> is null.</exception>
		public static bool VerifyPassword(
			string hashedPassword,
			string password)
		{
			ArgumentNullException.ThrowIfNull(password);

			var passwordUtf8Len = Encoding.UTF8.GetByteCount(password);
			Span<byte> passwordUtf8 = passwordUtf8Len > Constants.MaxStackAlloc ? new byte[passwordUtf8Len] : stackalloc byte[passwordUtf8Len];
			Encoding.UTF8.GetBytes(password, passwordUtf8);
			return VerifyPassword(hashedPassword, passwordUtf8);
		}
	}
}
```

---

## ⚙️ Native Interop: GenericHash.cs
```csharp

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		internal const int CRYPTO_GENERICHASH_BYTES = 32;
		internal const int CRYPTO_GENERICHASH_BYTES_MIN = 16;
		internal const int CRYPTO_GENERICHASH_BYTES_MAX = 64;
		internal const int CRYPTO_GENERICHASH_KEYBYTES = 32;
		internal const int CRYPTO_GENERICHASH_KEYBYTES_MIN = 16;
		internal const int CRYPTO_GENERICHASH_KEYBYTES_MAX = 64;


		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_generichash))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_generichash(
			Span<byte> output, nuint outputLength,
			ReadOnlySpan<byte> input, ulong inputLength,
			ReadOnlySpan<byte> key, nuint keyLength);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_generichash_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nuint crypto_generichash_statebytes();

		// write libraryimport for int crypto_generichash_init
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_generichash_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_generichash_init(
			Span<byte> state,
			ReadOnlySpan<byte> key, 
			nuint key_len,
			nuint hash_len);

		// write libraryimport for int crypto_generichash_update
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_generichash_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_generichash_update(
			Span<byte> state,
			ReadOnlySpan<byte> input,
			ulong input_len);

		// write libraryimport for int crypto_generichash_final
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_generichash_final))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_generichash_final(
			Span<byte> state,
			Span<byte> hash,
			nuint hash_len);

	}
}
```

---

## ⚙️ Native Interop: ShortHash.cs
```csharp
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		public const int CRYPTO_SHORTHASH_BYTES = 8;
		public const int CRYPTO_SHORTHASH_KEYBYTES = 16;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_shorthash))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_shorthash(
			Span<byte> hash,                  
			ReadOnlySpan<byte> input,           
			ulong input_len,                 
			ReadOnlySpan<byte> key);
	}
}
```

---

## ⚙️ Native Interop: PasswordHash.cs
```csharp
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{

		public const int CRYPTO_PWHASH_ALG_ARGON2I13 = 1;
		public const int CRYPTO_PWHASH_ALG_ARGON2ID13 = 2;
		public const int CRYPTO_PWHASH_ALG_DEFAULT = CRYPTO_PWHASH_ALG_ARGON2ID13;

		public const int CRYPTO_PWHASH_BYTES_MIN = 16;
		public const int CRYPTO_PWHASH_BYTES_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_PASSWD_MIN = 0;
		public const int CRYPTO_PWHASH_PASSWD_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_SALTBYTES = 16;
		public const int CRYPTO_PWHASH_STRBYTES = 128;

		public const string CRYPTO_PWHASH_STRPREFIX = "$argon2id$";

		public const int CRYPTO_PWHASH_OPSLIMIT_MIN = 1;
		public const int CRYPTO_PWHASH_OPSLIMIT_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_MEMLIMIT_MIN = 8192;
		public const int CRYPTO_PWHASH_MEMLIMIT_MAX = int.MaxValue;

		public const int CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE = 2;
		public const int CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE = 64 * 1024 * 1024; // 64 MB

		public const int CRYPTO_PWHASH_OPSLIMIT_MODERATE = 3;
		public const int CRYPTO_PWHASH_MEMLIMIT_MODERATE = 256 * 1024 * 1024; // 256 MB

		public const int CRYPTO_PWHASH_OPSLIMIT_SENSITIVE = 4;
		public const int CRYPTO_PWHASH_MEMLIMIT_SENSITIVE = 1024 * 1024 * 1024; // 1 GB

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_pwhash))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_pwhash(
			Span<byte> key,
			ulong output_len,
			ReadOnlySpan<byte> password,
			ulong password_len,
			ReadOnlySpan<byte> salt,
			ulong opsLimit,
			nuint memLimit,
			int algorithm);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_pwhash_str))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_pwhash_str(
			Span<byte> output, 
			ReadOnlySpan<byte> password, 
			ulong password_len, 
			ulong opsLimit,
			nuint memLimit 
		);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_pwhash_str_verify))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_pwhash_str_verify(
			ReadOnlySpan<byte> hashed_password,
			ReadOnlySpan<byte> password,
			ulong passwordLen
		);

	}
}
```

---

## 🧪 Tests: CryptoGenericHashTests.cs
```csharp
using LibSodium.Tests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibSodium.Net.Tests
{
	public  class CryptoGenericHashTests
	{

		[Test]
		public void ComputeHash_WithMemoryStreamAndArray_ProducesSameHash()
		{
			var key = new byte[CryptoGenericHash.KeyLen];
			RandomGenerator.Fill(key);

			var message = Encoding.UTF8.GetBytes("Hello, LibSodium!");

			using var memoryStream = new MemoryStream(message);
			var hashFromStream = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hashFromStream, memoryStream, key);

			var hashFromArray = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hashFromArray, message, key);

			hashFromStream.ShouldBe(hashFromArray);
		}

		[Test]
		[Arguments(0)]
		[Arguments(1)]
		[Arguments(8191)]
		[Arguments(8192)]
		[Arguments(8193)]
		public void ComputeHash_WithMemoryStreamAndArray_VariousSizes_ProducesSameHash(int size)
		{
			var key = new byte[CryptoGenericHash.KeyLen];
			RandomGenerator.Fill(key);

			var message = new byte[size];
			Random.Shared.NextBytes(message);

			using var memoryStream = new MemoryStream(message);

			var hashFromStream = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hashFromStream, memoryStream, key);

			var hashFromArray = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hashFromArray, message, key);

			hashFromStream.ShouldBe(hashFromArray);
		}


		[Test]
		public void ComputeHash_WithDifferentKeys_ProducesDifferentHashes()
		{
			var key1 = new byte[CryptoGenericHash.KeyLen];
			var key2 = new byte[CryptoGenericHash.KeyLen];
			RandomGenerator.Fill(key1);
			RandomGenerator.Fill(key2);

			var message = Encoding.UTF8.GetBytes("Hello, LibSodium!");

			var hash1 = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hash1, message, key1);

			var hash2 = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hash2, message, key2);

			hash1.ShouldNotBe(hash2);
		}

		[Test]
		public async Task ComputeHashAsync_WithMemoryStreamAndArray_ProducesSameHashAsync()
		{
			var key = new byte[CryptoGenericHash.KeyLen];
			RandomGenerator.Fill(key);

			var message = Encoding.UTF8.GetBytes("Hello, LibSodium!");

			using var memoryStream = new MemoryStream(message);
			var hashFromStreamAsync = new byte[CryptoGenericHash.HashLen];
			await CryptoGenericHash.ComputeHashAsync(hashFromStreamAsync, memoryStream, key);

			var hashFromArray = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(hashFromArray, message, key);

			hashFromStreamAsync.ShouldBe(hashFromArray);
		}

		[Test]
		public async Task ComputeHashAsync_WithCancellationToken_Success()
		{
			var key = new byte[CryptoGenericHash.KeyLen];
			RandomGenerator.Fill(key);

			var message = Encoding.UTF8.GetBytes("LibSodium async test!");

			using var memoryStream = new MemoryStream(message);
			var hashAsync = new byte[CryptoGenericHash.HashLen];

			var cts = new CancellationTokenSource();
			await CryptoGenericHash.ComputeHashAsync(hashAsync, memoryStream, key, cts.Token);

			var expectedHash = new byte[CryptoGenericHash.HashLen];
			CryptoGenericHash.ComputeHash(expectedHash, message, key);

			hashAsync.ShouldBe(expectedHash);
		}

		[Test]
		public void ComputeHash_EmptyMessage_EmptyKey_CorrectHash()
		{
			Span<byte> hash = stackalloc byte[32];
			CryptoGenericHash.ComputeHash(hash, Span<byte>.Empty, Span<byte>.Empty);
			var expected = Convert.FromHexString("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
			hash.ShouldBe(expected);
		}

		[Test]
		public void ComputeHash_ABCMessage_EmptyKey_CorrectHash()
		{
			var message = Encoding.UTF8.GetBytes("abc");
			Span<byte> hash = stackalloc byte[32];
			CryptoGenericHash.ComputeHash(hash, message, ReadOnlySpan<byte>.Empty);

			var expected = Convert.FromHexString("BDDD813C634239723171EF3FEE98579B94964E3BB1CB3E427262C8C068D52319");
			hash.ShouldBe(expected);
		}

		[Test]
		public void ComputeHash_HelloMessage_EmptyKey_CorrectHash()
		{
			var message = Encoding.UTF8.GetBytes("hello");
			Span<byte> hash = stackalloc byte[32];
			CryptoGenericHash.ComputeHash(hash, message, ReadOnlySpan<byte>.Empty);

			var expected = Convert.FromHexString("324DCF027DD4A30A932C441F365A25E86B173DEFA4B8E58948253471B81B72CF");
			hash.ShouldBe(expected);
		}

		[Test]
		public void ComputeHash512_EmptyMessage_EmptyKey_CorrectHash()
		{
			var message = Encoding.UTF8.GetBytes("");
			Span<byte> hash = stackalloc byte[64];
			CryptoGenericHash.ComputeHash(hash, message, ReadOnlySpan<byte>.Empty);

			var expected = Convert.FromHexString("786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE");
			hash.ToArray().ShouldBe(expected);
		}

		[Test]
		public void ComputeHash512_ABCMessage_EmptyKey_CorrectHash()
		{
			var message = Encoding.UTF8.GetBytes("abc");
			Span<byte> hash = stackalloc byte[64];
			CryptoGenericHash.ComputeHash(hash, message, ReadOnlySpan<byte>.Empty);

			var expected = Convert.FromHexString("BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923");
			hash.ToArray().ShouldBe(expected);
		}

		[Test]
		public void ComputeHash512_HelloMessage_EmptyKey_CorrectHash()
		{
			var message = Encoding.UTF8.GetBytes("hello");
			Span<byte> hash = stackalloc byte[64];
			CryptoGenericHash.ComputeHash(hash, message, ReadOnlySpan<byte>.Empty);

			var expected = Convert.FromHexString("E4CFA39A3D37BE31C59609E807970799CAA68A19BFAA15135F165085E01D41A65BA1E1B146AEB6BD0092B49EAC214C103CCFA3A365954BBBE52F74A2B3620C94");
			hash.ToArray().ShouldBe(expected);
		}
	}
}
```

---

## 🧪 Tests: CryptoShortHashTests.cs

```csharp
using System.Text;
using LibSodium;
namespace LibSodium.Tests;

public class CryptoShortHashTests
{
    private static readonly byte[] FixedKey = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");

    [Test]
    public void ComputeHash_EmptyMessage_KnownKey_CorrectHash()
    {
        var message = ReadOnlySpan<byte>.Empty;
        Span<byte> hash = stackalloc byte[CryptoShortHash.HashLen];
        CryptoShortHash.ComputeHash(hash, message, FixedKey);

        var expected = Convert.FromHexString("310E0EDD47DB6F72");
		hash.ShouldBe(expected);
    }

    [Test]
    public void ComputeHash_ABCMessage_KnownKey_CorrectHash()
    {
        var message = Encoding.UTF8.GetBytes("abc");
        Span<byte> hash = stackalloc byte[CryptoShortHash.HashLen];
        CryptoShortHash.ComputeHash(hash, message, FixedKey);

        var expected = Convert.FromHexString("A50720AA53FABC5D");
		hash.ShouldBe(expected);
    }

    [Test]
    public void ComputeHash_HelloMessage_KnownKey_CorrectHash()
    {
        var message = Encoding.UTF8.GetBytes("hello");
        Span<byte> hash = stackalloc byte[CryptoShortHash.HashLen];
        CryptoShortHash.ComputeHash(hash, message, FixedKey);

        var expected = Convert.FromHexString("81DF675798B34F00");
		hash.ShouldBe(expected);
    }

    [Test]
    public void ComputeHash_DifferentKeys_ProduceDifferentHashes()
    {
        var message = Encoding.UTF8.GetBytes("hello");
        Span<byte> hash1 = stackalloc byte[CryptoShortHash.HashLen];
        Span<byte> hash2 = stackalloc byte[CryptoShortHash.HashLen];

        CryptoShortHash.ComputeHash(hash1, message, FixedKey);

        var otherKey = new byte[CryptoShortHash.KeyLen];
        RandomGenerator.Fill(otherKey);
        CryptoShortHash.ComputeHash(hash2, message, otherKey);

        hash1.ShouldNotBe(hash2);
    }
}
```

---

## 🧪 Tests: CryptoPasswordHashTests.cs
```csharp
using System.Text;
using LibSodium;
using LibSodium.Tests;

public class CryptoPasswordHashTests
{
	[Test]
	public void DeriveKey_SpanOverload_WithSameInputs_ProducesSameKey()
	{
		Span<byte> salt = stackalloc byte[CryptoPasswordHash.SaltLen];
		RandomGenerator.Fill(salt);
		Span<byte> key1 = stackalloc byte[32];
		Span<byte> key2 = stackalloc byte[32];
		byte[] passwordBytes = Encoding.UTF8.GetBytes("span-password");

		CryptoPasswordHash.DeriveKey(key1, passwordBytes, salt);
		CryptoPasswordHash.DeriveKey(key2, passwordBytes, salt);

		key1.ShouldBe(key2);
	}

	[Test]
	public void HashPassword_HasExpectedPrefix()
	{
		string hash = CryptoPasswordHash.HashPassword("prefix-check");
		hash.ShouldStartWith(CryptoPasswordHash.Prefix);
	}

	[Test]
	public void HashPassword_SamePassword_ProducesDifferentHashes()
	{
		string password = "non-deterministic";
		string hash1 = CryptoPasswordHash.HashPassword(password);
		string hash2 = CryptoPasswordHash.HashPassword(password);

		hash1.ShouldNotBe(hash2);
	}

	[Test]
	public void VerifyPassword_WithTamperedHash_ShouldFail()
	{
		string password = "tamper-proof";
		string hash = CryptoPasswordHash.HashPassword(password);

		char[] chars = hash.ToCharArray();
		chars[^2] = chars[^2] == 'a' ? 'b' : 'a';
		string tampered = new string(chars);

		CryptoPasswordHash.VerifyPassword(tampered, password).ShouldBeFalse();
	}

	[Test]
	public void HashPassword_SpanOverload_And_VerifyPassword_Succeeds()
	{
		byte[] passwordBytes = Encoding.UTF8.GetBytes("span-pass-hash");

		string hash = CryptoPasswordHash.HashPassword(passwordBytes);

		CryptoPasswordHash.VerifyPassword(hash, passwordBytes).ShouldBeTrue();
	}

	[Test]
	public void VerifyPassword_SpanOverload_WithWrongPassword_ShouldFail()
	{
		byte[] password = Encoding.UTF8.GetBytes("right-pass");
		byte[] wrong = Encoding.UTF8.GetBytes("wrong-pass");

		string hash = CryptoPasswordHash.HashPassword(password);

		CryptoPasswordHash.VerifyPassword(hash, wrong).ShouldBeFalse();
	}

	[Test]
	public void DeriveKey_WithValidInputs_ShouldFillKey()
	{
		Span<byte> key = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[CryptoPasswordHash.SaltLen];
		string password = "p@ssw0rd!";

		RandomGenerator.Fill(salt);
		CryptoPasswordHash.DeriveKey(key, password, salt);
		SecureMemory.IsZero(key).ShouldBeFalse();
	}

	[Test]
	public void DeriveKey_WithDifferentSalts_ProducesDifferentKeys()
	{
		string password = Guid.NewGuid().ToString();
		Span<byte> salt1 = stackalloc byte[CryptoPasswordHash.SaltLen];
		Span<byte> salt2 = stackalloc byte[CryptoPasswordHash.SaltLen];
		RandomGenerator.Fill(salt1);
		RandomGenerator.Fill(salt2);

		Span<byte> key1 = stackalloc byte[32];
		Span<byte> key2 = stackalloc byte[32];

		CryptoPasswordHash.DeriveKey(key1, password, salt1);
		CryptoPasswordHash.DeriveKey(key2, password, salt2);

		key1.ShouldNotBe(key2);
	}

	[Test]
	public void DeriveKey_WithDifferentPasswords_ProducesDifferentKeys()
	{
		string password1 = Guid.NewGuid().ToString();
		string password2 = Guid.NewGuid().ToString();
		Span<byte> salt = stackalloc byte[CryptoPasswordHash.SaltLen];
		RandomGenerator.Fill(salt);

		Span<byte> key1 = stackalloc byte[32];
		Span<byte> key2 = stackalloc byte[32];

		CryptoPasswordHash.DeriveKey(key1, password1, salt);
		CryptoPasswordHash.DeriveKey(key2, password2, salt);

		key1.ShouldNotBe(key2);
	}

	[Test]
	public void DeriveKey_WithSameInputs_ProducesSameKey()
	{
		string password = Guid.NewGuid().ToString();
		Span<byte> salt = stackalloc byte[CryptoPasswordHash.SaltLen];
		RandomGenerator.Fill(salt);

		Span<byte> key1 = stackalloc byte[32];
		Span<byte> key2 = stackalloc byte[32];

		CryptoPasswordHash.DeriveKey(key1, password, salt);
		CryptoPasswordHash.DeriveKey(key2, password, salt);

		key1.ShouldBe(key2);
	}

	[Test]
	public void DeriveKey_WithShortSalt_ShouldThrow()
	{
		byte[] key = new byte[32];
		string password = "correcthorsebatterystaple";
		byte[] salt = new byte[CryptoPasswordHash.SaltLen - 1];

		AssertLite.Throws<ArgumentException>(() => CryptoPasswordHash.DeriveKey(key, password, salt));
	}

	[Test]
	public void HashPassword_And_VerifyPassword_ShouldSucceed()
	{
		string password = "correct horse battery staple";

		string hash = CryptoPasswordHash.HashPassword(password);

		CryptoPasswordHash.VerifyPassword(hash, password).ShouldBeTrue();
	}

	[Test]
	public void VerifyPassword_WithWrongPassword_ShouldFail()
	{
		string password = "super secret";
		string wrongPassword = "not the same";

		string hash = CryptoPasswordHash.HashPassword(password);

		CryptoPasswordHash.VerifyPassword(hash, wrongPassword).ShouldBeFalse();
	}

	[Test]
	public void HashPassword_WithEmptyPassword_IsValid()
	{
		string password = string.Empty;

		string hash = CryptoPasswordHash.HashPassword(password);

		CryptoPasswordHash.VerifyPassword(hash, password).ShouldBeTrue();
	}
	// tests nuevos

	[Test]
	public void DeriveKey_WithInvalidKeyLength_ShouldThrow()
	{
		var key = new byte[CryptoPasswordHash.MinKeyLen - 1];
		var salt = new byte[CryptoPasswordHash.SaltLen];
		string password = "short-key";
		RandomGenerator.Fill(salt);

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHash.DeriveKey(key, password, salt));
	}

	[Test]
	public void DeriveKey_WithTooFewIterations_ShouldThrow()
	{
		var key = new byte[32];
		var salt = new byte[CryptoPasswordHash.SaltLen];
		string password = "few-iters";
		RandomGenerator.Fill(salt);

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHash.DeriveKey(key, password, salt, iterations: CryptoPasswordHash.MinIterations - 1));
	}

	[Test]
	public void DeriveKey_WithTooLittleMemory_ShouldThrow()
	{
		var key = new byte[32];
		var salt = new byte[CryptoPasswordHash.SaltLen];
		string password = "low-mem";
		RandomGenerator.Fill(salt);

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHash.DeriveKey(key, password, salt, requiredMemoryLen: CryptoPasswordHash.MinMemoryLen - 1));
	}

	[Test]
	public void DeriveKey_WithArgon2i13_And_TooFewIterations_ShouldThrow()
	{
		var key = new byte[32];
		var salt = new byte[CryptoPasswordHash.SaltLen];
		string password = "argon2i-fail";
		RandomGenerator.Fill(salt);

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHash.DeriveKey(key, password, salt,
				iterations: 2,
				algorithm: PasswordHashAlgorithm.Argon2i13));
	}

	[Test]
	public void DeriveKey_WithArgon2id13_ShouldSucceed()
	{
		var key = new byte[32];
		var salt = new byte[CryptoPasswordHash.SaltLen];
		string password = "argon2id-ok";
		RandomGenerator.Fill(salt);

		CryptoPasswordHash.DeriveKey(key, password, salt,
			iterations: 4,
			requiredMemoryLen: CryptoPasswordHash.ModerateMemoryLen,
			algorithm: PasswordHashAlgorithm.Argon2id13);

		SecureMemory.IsZero(key).ShouldBeFalse();
	}

	[Test]
	public void DeriveKey_WithArgon2i13_ShouldSucceed()
	{
		Span<byte> key = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[CryptoPasswordHash.SaltLen];
		string password = "argon2i-ok";
		RandomGenerator.Fill(salt);

		CryptoPasswordHash.DeriveKey(key, password, salt,
			iterations: 3,
			requiredMemoryLen: CryptoPasswordHash.ModerateMemoryLen,
			algorithm: PasswordHashAlgorithm.Argon2i13);

		SecureMemory.IsZero(key).ShouldBeFalse();
	}

	// more tests
	[Test]
	public void HashPassword_WithTooFewIterations_ShouldThrow()
	{
		string password = "p";

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHash.HashPassword(password, iterations: CryptoPasswordHash.MinIterations - 1));
	}

	[Test]
	public void HashPassword_WithTooLittleMemory_ShouldThrow()
	{
		string password = "p";

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHash.HashPassword(password, requiredMemoryLen: CryptoPasswordHash.MinMemoryLen - 1));
	}

	[Test]
	public void HashPassword_SpanOverload_WithTooFewIterations_ShouldThrow()
	{
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
		{
			Span<byte> password = stackalloc byte[1];
			CryptoPasswordHash.HashPassword(password, iterations: CryptoPasswordHash.MinIterations - 1);
		});
	}

	[Test]
	public void HashPassword_SpanOverload_WithTooLittleMemory_ShouldThrow()
	{
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
		{
			Span<byte> password = stackalloc byte[1];
			CryptoPasswordHash.HashPassword(password, requiredMemoryLen: CryptoPasswordHash.MinMemoryLen - 1);
		});
	}

	[Test]
	public void VerifyPassword_WithNullHash_ShouldThrow()
	{
		string password = "pw";

		AssertLite.Throws<ArgumentNullException>(() =>
			CryptoPasswordHash.VerifyPassword(null!, password));
	}

	[Test]
	public void VerifyPassword_WithInvalidPrefix_ShouldReturnFalse()
	{
		string password = "pw";
		string hash = "invalidprefix$argon2id...";

		CryptoPasswordHash.VerifyPassword(hash, password).ShouldBeFalse();
	}

	[Test]
	public void VerifyPassword_WithTruncatedHash_ShouldReturnFalse()
	{
		string password = "pw";
		string hash = CryptoPasswordHash.HashPassword(password).Substring(0, 10);

		CryptoPasswordHash.VerifyPassword(hash, password).ShouldBeFalse();
	}

	[Test]
	public void VerifyPassword_SpanOverload_WithInvalidPrefix_ShouldReturnFalse()
	{
		Span<byte> password = stackalloc byte[] { 1, 2, 3 };
		string hash = "badprefix$argon2id...";

		CryptoPasswordHash.VerifyPassword(hash, password).ShouldBeFalse();
	}
}
```
# CryptoShaHash.cs source code

```csharp
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		public const int CRYPTO_HASH_SHA256_BYTES = 32;
		public const int CRYPTO_HASH_SHA512_BYTES = 64;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha256))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha256(Span<byte> hash, ReadOnlySpan<byte> input, ulong input_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha512))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha512(Span<byte> hash, ReadOnlySpan<byte> input, ulong input_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha256_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nuint crypto_hash_sha256_statebytes();

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha256_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha256_init(Span<byte> state);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha256_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha256_update(Span<byte> state, ReadOnlySpan<byte> input, ulong input_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha256_final))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha256_final(Span<byte> state, Span<byte> hash);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha512_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial nuint crypto_hash_sha512_statebytes();

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha512_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha512_init(Span<byte> state);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha512_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha512_update(Span<byte> state, ReadOnlySpan<byte> input, ulong input_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_hash_sha512_final))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_hash_sha512_final(Span<byte> state, Span<byte> hash);
	}
}
```

# CryptoSha256 source code

```csharp
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using LibSodium.LowLevel;

namespace LibSodium;

/// <summary>
/// Computes and verifies HMAC-SHA-256 message authentication codes.
/// </summary>
public static class CryptoHmacSha256
{
	/// <summary>
	/// Length of the HMAC output in bytes (32).
	/// </summary>
	public static readonly int MacLen = HmacSha256.MacLen;

	/// <summary>
	/// Length of the secret key in bytes (32).
	/// </summary>
	public static readonly int KeyLen = HmacSha256.KeyLen;

	/// <summary>
	/// Computes an HMAC-SHA-256 authentication code for the given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to authenticate.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <returns>The length of the MAC written (always 32).</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static int ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> mac)
		=> CryptoMac<HmacSha256>.ComputeMac(key, message, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-256 authentication code against a given message.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="message">The message to verify.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	public static bool VerifyMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha256>.VerifyMac(key, message, mac);

	/// <summary>
	/// Generates a random 32-byte key suitable for HMAC-SHA-256.
	/// </summary>
	/// <param name="key">A buffer to receive the generated key (must be 32 bytes).</param>
	public static void GenerateKey(Span<byte> key)
		=> CryptoMac<HmacSha256>.GenerateKey(key);

	/// <summary>
	/// Computes an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static void ComputeMac(ReadOnlySpan<byte> key, Stream messageStream, Span<byte> mac)
		=> CryptoMac<HmacSha256>.ComputeMac(key, messageStream, mac);

	/// <summary>
	/// Verifies an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	public static bool VerifyMac(ReadOnlySpan<byte> key, Stream messageStream, ReadOnlySpan<byte> mac)
		=> CryptoMac<HmacSha256>.VerifyMac(key, messageStream, mac);

	/// <summary>
	/// Asynchronously computes an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">A buffer to receive the 32-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="key"/> or <paramref name="mac"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the MAC computation fails internally.</exception>
	public static Task ComputeMacAsync(ReadOnlyMemory<byte> key, Stream messageStream, Memory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha256>.ComputeMacAsync(key, messageStream, mac, cancellationToken);

	/// <summary>
	/// Asynchronously verifies an HMAC-SHA-256 authentication code from a stream.
	/// </summary>
	/// <param name="key">A 32-byte secret key.</param>
	/// <param name="messageStream">A stream containing the message.</param>
	/// <param name="mac">The expected 32-byte MAC.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
	public static Task<bool> VerifyMacAsync(ReadOnlyMemory<byte> key, Stream messageStream, ReadOnlyMemory<byte> mac, CancellationToken cancellationToken = default)
		=> CryptoMac<HmacSha256>.VerifyMacAsync(key, messageStream, mac, cancellationToken);


	/// <summary>
	/// Creates an incremental hash object using the HMAC-SHA256 algorithm.
	/// </summary>
	/// <remarks>The returned <see cref="ICryptoIncrementalHash"/> can be used to compute the HMAC-SHA256 hash
	/// incrementally by processing data in chunks. This is useful for scenarios where the data to be hashed is too large
	/// to fit in memory or is received in a streaming fashion.</remarks>
	/// <param name="key">The cryptographic key (32 bytes) to use for the HMAC-SHA256 computation.</param>
	/// <returns>An <see cref="ICryptoIncrementalHash"/> instance that allows incremental computation of the HMAC-SHA256 hash.</returns>
	public static ICryptoIncrementalHash CreateIncrementalMac(ReadOnlySpan<byte> key)
	{
		return new CryptoMacIncremental<HmacSha256>(key);
	}
}

```
## CryptoSha512 source code

```csharp
using LibSodium.Interop;

namespace LibSodium;

/// <summary>
/// Provides one‑shot and streaming <b>SHA‑512</b> hashing helpers built on libsodium’s
/// <c>crypto_hash_sha512</c> API.
/// </summary>
public static class CryptoSha512
{
	/// <summary>Hash length in bytes (64).</summary>
	public const int HashLen = Native.CRYPTO_HASH_SHA512_BYTES;

	/// <summary>
	/// Size of the native <c>crypto_hash_sha512_state</c> structure in bytes (implementation‑defined).
	/// Used for stack‑allocating the state when hashing streams.
	/// </summary>
	internal static readonly int StateLen = (int)Native.crypto_hash_sha512_statebytes();

	/// <summary>
	/// Computes a SHA‑512 hash of <paramref name="message"/> and stores the result in
	/// <paramref name="hash"/>.
	/// </summary>
	/// <param name="hash">Destination buffer (64 bytes).</param>
	/// <param name="message">Message to hash.</param>
	/// <exception cref="ArgumentException">If <paramref name="hash"/> length ≠ 64.</exception>
	/// <exception cref="LibSodiumException">If the native function returns non‑zero.</exception>
	public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
		=> CryptoKeyLessHash<LowLevel.Sha512>.ComputeHash(hash, message);

	/// <summary>
	/// Computes a SHA‑512 hash over the entire contents of the supplied <see cref="Stream"/>.
	/// </summary>
	/// <param name="hash">Destination buffer (64 bytes) that receives the final hash.</param>
	/// <param name="input">The input stream to read and hash. The stream is read until its end.</param>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is <c>null</c>.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="hash"/> is not exactly 64 bytes.</exception>
	/// <exception cref="LibSodiumException">Thrown if the underlying libsodium call fails.</exception>
	/// <remarks>
	/// The method processes the stream in buffered chunks of <c>8 KiB</c>, keeping memory usage low even for very large inputs.
	/// </remarks>
	public static void ComputeHash(Span<byte> hash, Stream input)
		=> CryptoKeyLessHash<LowLevel.Sha512>.ComputeHash(hash, input);

	/// <summary>
	/// Asynchronously computes a SHA‑512 hash over the supplied <see cref="Stream"/>, writing the
	/// result into <paramref name="hash"/>.
	/// </summary>
	/// <param name="hash">Destination memory buffer (64 bytes) that receives the final hash.</param>
	/// <param name="input">The input stream to read and hash. The stream is read until its end.</param>
	/// <param name="cancellationToken">Token that can be used to cancel the asynchronous operation.</param>
	/// <returns>A task that completes when the hash has been fully computed and written.</returns>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is <c>null</c>.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="hash"/> is not exactly 64 bytes.</exception>
	/// <exception cref="LibSodiumException">Thrown if the underlying libsodium call fails.</exception>
	/// <remarks>
	/// The method reads the stream in buffered chunks of <c>8 KiB</c> and is fully asynchronous, making it suitable for
	/// hashing network streams or large files without blocking the calling thread.
	/// </remarks>
	public static async Task ComputeHashAsync(Memory<byte> hash, Stream input, CancellationToken cancellationToken = default)
		=> await CryptoKeyLessHash<LowLevel.Sha512>.ComputeHashAsync(hash, input, cancellationToken).ConfigureAwait(false);


	/// <summary>
	/// Creates a new instance of an incremental hash computation object using the SHA-512 algorithm.
	/// </summary>
	/// <remarks>This method provides an object for computing a hash incrementally, which is useful for processing
	/// large data streams or when the data to be hashed is not available all at once.</remarks>
	/// <returns>An <see cref="ICryptoIncrementalHash"/> instance that allows incremental computation of a SHA-512 hash.</returns>
	/// <exception cref="LibSodiumException">Thrown if the underlying libsodium call fails.</exception>
	public static ICryptoIncrementalHash CreateIncrementalHash()
	{
		return new CryptoKeyLessHashIncremental<LowLevel.Sha512>();
	}
}

```

## Source Code CryptoKeyLessHashIncremental.cs

```csharp
using LibSodium.LowLevel;

namespace LibSodium;

/// <summary>
/// Incremental hashing engine for algorithms that do not require a key (e.g., SHA‑2).
/// </summary>
/// <typeparam name="T">The underlying hash algorithm.</typeparam>
internal sealed class CryptoKeyLessHashIncremental<T> : ICryptoIncrementalHash
	where T : IKeyLessHash
{
	private readonly byte[] state = new byte[T.StateLen];
	private bool isFinalized = false;
	private bool isDisposed = false;

	/// <summary>
	/// Initializes a new incremental hash instance for algorithm <typeparamref name="T"/>.
	/// </summary>
	public CryptoKeyLessHashIncremental()
	{
		if (T.Init(state) != 0)
			throw new LibSodiumException("Failed to initialize the incremental hashing operation.");
	}

	private void CheckDisposed()
	{
		if (isDisposed)
			throw new ObjectDisposedException(nameof(CryptoKeyLessHashIncremental<T>), "The incremental hashing instance has already been disposed.");
	}

	/// <summary>
	/// Appends data to the ongoing hash computation.
	/// </summary>
	/// <param name="data">The input data to append.</param>
	/// <exception cref="ObjectDisposedException">If the instance has been disposed.</exception>
	/// <exception cref="InvalidOperationException">If <see cref="Final"/> has already been called.</exception>
	public void Update(ReadOnlySpan<byte> data)
	{
		CheckDisposed();
		if (isFinalized)
			throw new InvalidOperationException("Cannot update after the incremental hashing operation has been finalized.");

		if (T.Update(state, data) != 0)
			throw new LibSodiumException("Failed to update the hash state.");
	}

	/// <summary>
	/// Finalizes the hash computation and writes the result to the specified buffer.
	/// </summary>
	/// <param name="hash">The buffer to receive the final hash. Must be exactly <c>T.HashLen</c> bytes.</param>
	/// <exception cref="ObjectDisposedException">If the instance has been disposed.</exception>
	/// <exception cref="InvalidOperationException">If called more than once.</exception>
	/// <exception cref="ArgumentException">If the buffer length is invalid.</exception>
	public void Final(Span<byte> hash)
	{
		CheckDisposed();
		if (isFinalized)
			throw new InvalidOperationException("Hash has already been finalized.");

		if (hash.Length != T.HashLen)
			throw new ArgumentException($"Hash must be exactly {T.HashLen} bytes.", nameof(hash));

		if (T.Final(state, hash) != 0)
			throw new LibSodiumException("Failed to finalize the hash computation.");

		isFinalized = true;
		SecureMemory.MemZero(state);
	}

	/// <summary>
	/// Disposes the hash state, zeroing it if not already finalized.
	/// </summary>
	public void Dispose()
	{
		if (isDisposed) return;
		isDisposed = true;

		if (!isFinalized)
			SecureMemory.MemZero(state);
	}
}

```

## Source code CryptoKeyLessHash.cs

```csharp
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using LibSodium.LowLevel;

namespace LibSodium;

/// <summary>
/// Provides generic one-shot and streaming helpers for key-less hash functions like SHA‑2.
/// </summary>
/// <typeparam name="T">The hash algorithm (e.g., <see cref="Sha256"/>).</typeparam>
internal static class CryptoKeyLessHash<T> where T : IKeyLessHash
{
	/// <summary>
	/// Gets the length of the output hash in bytes.
	/// </summary>
	public static int HashLen => T.HashLen;

	/// <summary>
	/// Gets the size of the internal hashing state structure.
	/// </summary>
	public static int StateLen => T.StateLen;

	/// <summary>
	/// Computes a hash of <paramref name="message"/> and stores the result in <paramref name="hash"/>.
	/// </summary>
	/// <param name="hash">Destination buffer. Must be <see cref="HashLen"/> bytes.</param>
	/// <param name="message">Message to hash.</param>
	public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
	{
		if (hash.Length != HashLen)
			throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));

		LibraryInitializer.EnsureInitialized();
		if (T.ComputeHash(hash, message) != 0)
			throw new LibSodiumException("Hashing failed.");
	}

	/// <summary>
	/// Computes a hash over the contents of a stream.
	/// </summary>
	/// <param name="hash">The buffer that will receive the final hash. Must be <see cref="HashLen"/> bytes.</param>
	/// <param name="input">The input stream to read and hash.</param>
	public static void ComputeHash(Span<byte> hash, Stream input)
	{
		ArgumentNullException.ThrowIfNull(input);
		using var h = CreateIncrementalHash();
		h.Compute(input, hash);
	}

	/// <summary>
	/// Asynchronously computes a hash over the contents of a stream.
	/// </summary>
	/// <param name="hash">The buffer that will receive the final hash. Must be <see cref="HashLen"/> bytes.</param>
	/// <param name="input">The input stream to read and hash.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	public static Task ComputeHashAsync(Memory<byte> hash, Stream input, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(input);
		using var h = CreateIncrementalHash();
		return h.ComputeAsync(input, hash, cancellationToken);
	}

	/// <summary>
	/// Creates an incremental hashing engine for algorithm <typeparamref name="T"/>.
	/// </summary>
	/// <returns>A new <see cref="ICryptoIncrementalHash"/> instance.</returns>
	public static ICryptoIncrementalHash CreateIncrementalHash()
		=> new CryptoKeyLessHashIncremental<T>();
}

```

## Source code ICryptoIncrementalHash.cs

```csharp
using System.Buffers;

namespace LibSodium;

/// <summary>
/// Represents an incremental hash or MAC calculator that processes data in chunks and produces a fixed-size output.
/// </summary>
public interface ICryptoIncrementalHash : IDisposable
{
	/// <summary>
	/// Appends data to the ongoing hash or MAC computation.
	/// </summary>
	/// <param name="data">The input data to append. May be empty.</param>
	void Update(ReadOnlySpan<byte> data);

	/// <summary>
	/// Finalizes the hash or MAC computation and writes the result to the specified buffer.
	/// </summary>
	/// <param name="hash">The buffer where the final result will be written. Must match the expected output length.</param>
	/// <exception cref="InvalidOperationException">Thrown if called more than once.</exception>
	void Final(Span<byte> hash);


}

internal static class CryptoIncrementalHashExtensions
{
	/// <summary>
	/// Processes all data from the specified stream and finalizes the hash or MAC computation.
	/// </summary>
	/// <param name="incrementalHash"></param>
	/// <param name="input">The input stream to read and process. Cannot be null.</param>
	/// <param name="hash">The buffer where the final result will be written. Must match the expected output length.</param>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="hash"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the computation fails internally.</exception>
	public static void Compute(this ICryptoIncrementalHash incrementalHash, Stream input, Span<byte> hash)
	{
		ArgumentNullException.ThrowIfNull(input);

		byte[] buffer = ArrayPool<byte>.Shared.Rent(Constants.DefaultBufferLen);
		try
		{
			int read;
			while ((read = input.Read(buffer, 0, Constants.DefaultBufferLen)) > 0)
			{
				incrementalHash.Update(buffer.AsSpan(0, read));
			}
			incrementalHash.Final(hash);
		}
		finally
		{
			SecureMemory.MemZero(buffer);
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	/// <summary>
	/// Asynchronously processes all data from the specified stream and finalizes the hash or MAC computation.
	/// </summary>
	/// <param name="incrementalHash">The incremental hash used to compute the hash over the stream</param>
	/// <param name="input">The input stream to read and process. Cannot be null.</param>
	/// <param name="hash">The memory buffer where the final result will be written. Must match the expected output length.</param>
	/// <param name="cancellationToken">A cancellation token to abort the operation if needed.</param>
	/// <returns>A task that completes when the final result has been written to <paramref name="hash"/>.</returns>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
	/// <exception cref="ArgumentException">Thrown if <paramref name="hash"/> has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the computation fails internally.</exception>
	public static async Task ComputeAsync(this ICryptoIncrementalHash incrementalHash, Stream input, Memory<byte> hash, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(input);

		byte[] buffer = ArrayPool<byte>.Shared.Rent(Constants.DefaultBufferLen);
		try
		{
			int read;
			while ((read = await input.ReadAsync(buffer, 0, Constants.DefaultBufferLen, cancellationToken).ConfigureAwait(false)) > 0)
			{
				incrementalHash.Update(buffer.AsSpan(0, read));
			}
			incrementalHash.Final(hash.Span);
		}
		finally
		{
			SecureMemory.MemZero(buffer);
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

}
```

## Source Code IKeyLessHash.cs

```csharp
namespace LibSodium.LowLevel;

/// <summary>
/// Defines a unified interface for hash functions like SHA-2.
/// Supports one-shot and incremental hashing.
/// </summary>
internal interface IKeyLessHash
{
	/// <summary>
	/// Length of the hash output in bytes.
	/// </summary>
	static abstract int HashLen { get; }

	/// <summary>
	/// Length of the internal state in bytes.
	/// </summary>
	static abstract int StateLen { get; }

	/// <summary>
	/// Computes the hash for the given message.
	/// </summary>
	/// <param name="hash">Output buffer. Must be exactly <see cref="HashLen"/> bytes.</param>
	/// <param name="message">Input message to hash.</param>
	/// <returns>Zero on success; non-zero on failure.</returns>
	static abstract int ComputeHash(
		Span<byte> hash,
		ReadOnlySpan<byte> message);

	/// <summary>
	/// Initializes the hashing state.
	/// </summary>
	/// <param name="state">State buffer. Must be <see cref="StateLen"/> bytes.</param>
	/// <returns>Zero on success; non-zero on failure.</returns>
	static abstract int Init(Span<byte> state);

	/// <summary>
	/// Updates the hashing state with more data.
	/// </summary>
	/// <param name="state">State buffer previously initialized by <see cref="Init"/>.</param>
	/// <param name="message">Data to append to the hash computation.</param>
	/// <returns>Zero on success; non-zero on failure.</returns>
	static abstract int Update(Span<byte> state, ReadOnlySpan<byte> message);

	/// <summary>
	/// Finalizes the hash computation and writes the output.
	/// </summary>
	/// <param name="state">State buffer previously initialized by <see cref="Init"/>.</param>
	/// <param name="hash">Output buffer. Must be exactly <see cref="HashLen"/> bytes.</param>
	/// <returns>Zero on success; non-zero on failure.</returns>
	static abstract int Final(Span<byte> state, Span<byte> hash);
}
```

## Source Code Sha256.cs

```csharp
using LibSodium.Interop;

namespace LibSodium.LowLevel;

/// <summary>
/// Low-level wrapper for libsodium’s SHA‑256 implementation.
/// </summary>
internal readonly struct Sha256 : IKeyLessHash
{
	public static int HashLen => Native.CRYPTO_HASH_SHA256_BYTES;
	public static int StateLen => (int)Native.crypto_hash_sha256_statebytes();

	public static int ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
		=> Native.crypto_hash_sha256(hash, message, (ulong)message.Length);

	public static int Init(Span<byte> state)
		=> Native.crypto_hash_sha256_init(state);

	public static int Update(Span<byte> state, ReadOnlySpan<byte> message)
		=> Native.crypto_hash_sha256_update(state, message, (ulong)message.Length);

	public static int Final(Span<byte> state, Span<byte> hash)
		=> Native.crypto_hash_sha256_final(state, hash);
}

```

## Source Code Sha512.cs

```csharp
using LibSodium.Interop;

namespace LibSodium.LowLevel;

/// <summary>
/// Low-level wrapper for libsodium’s SHA‑512 implementation.
/// </summary>
internal readonly struct Sha512 : IKeyLessHash
{
	public static int HashLen => Native.CRYPTO_HASH_SHA512_BYTES;
	public static int StateLen => (int)Native.crypto_hash_sha512_statebytes();

	public static int ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
		=> Native.crypto_hash_sha512(hash, message, (ulong)message.Length);

	public static int Init(Span<byte> state)
		=> Native.crypto_hash_sha512_init(state);

	public static int Update(Span<byte> state, ReadOnlySpan<byte> message)
		=> Native.crypto_hash_sha512_update(state, message, (ulong)message.Length);

	public static int Final(Span<byte> state, Span<byte> hash)
		=> Native.crypto_hash_sha512_final(state, hash);
}
```

## Source Coce CryptoSha2Tests.cs

```csharp
using System.Security.Cryptography;
using LibSodium.Tests;

namespace LibSodium.Net.Tests;

public class CryptoSha2Tests
{
	// ── SHA‑256 ──────────────────────────────────────────────────────────────

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(17)]
	[Arguments(64)]
	[Arguments(1024)]
	public void ComputeHash256_Array_MatchesSystem(int size)
	{
		var message = new byte[size];
		RandomGenerator.Fill(message);

		Span<byte> hash = stackalloc byte[CryptoSha256.HashLen];
		CryptoSha256.ComputeHash(hash, message);

		var expected = SHA256.HashData(message);
		hash.ShouldBe(expected);
	}

	[Test]
	public void ComputeHash256_Stream_MatchesSystem()
	{
		var message = new byte[150_000];
		RandomGenerator.Fill(message);

		using var ms = new MemoryStream(message);
		Span<byte> hash = stackalloc byte[CryptoSha256.HashLen];
		CryptoSha256.ComputeHash(hash, ms);

		var expected = SHA256.HashData(message);
		hash.ShouldBe(expected);
	}

	[Test]
	public void ComputeHash256_InvalidHashBuffer_ShouldThrow()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> msg = stackalloc byte[1] { 0x01 };
			Span<byte> small = stackalloc byte[CryptoSha256.HashLen - 1];
			CryptoSha256.ComputeHash(small, msg);
		});
	}

	[Test]
	public void ComputeHash256_OversizedHashBuffer_ShouldThrow()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> msg = stackalloc byte[1] { 0x01 };
			Span<byte> large = stackalloc byte[CryptoSha256.HashLen + 1];
			CryptoSha256.ComputeHash(large, msg);
		});
	}

	[Test]
	public void ComputeHash256_NullStream_ShouldThrow()
	{
		AssertLite.Throws<ArgumentNullException>(() =>
		{
			Span<byte> hash = stackalloc byte[CryptoSha256.HashLen];
			Stream? s = null;
			CryptoSha256.ComputeHash(hash, s!);
		});
	}

	// ── SHA‑512 ──────────────────────────────────────────────────────────────

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(17)]
	[Arguments(64)]
	[Arguments(1024)]
	public void ComputeHash512_Array_MatchesSystem(int size)
	{
		var message = new byte[size];
		RandomGenerator.Fill(message);

		Span<byte> hash = stackalloc byte[CryptoSha512.HashLen];
		CryptoSha512.ComputeHash(hash, message);

		var expected = SHA512.HashData(message);
		hash.ShouldBe(expected);
	}

	[Test]
	public void ComputeHash512_Stream_MatchesSystem()
	{
		var message = new byte[150_000];
		RandomGenerator.Fill(message);

		using var ms = new MemoryStream(message);
		Span<byte> hash = stackalloc byte[CryptoSha512.HashLen];
		CryptoSha512.ComputeHash(hash, ms);

		var expected = SHA512.HashData(message);
		hash.ShouldBe(expected);
	}

	[Test]
	public void ComputeHash512_InvalidHashBuffer_ShouldThrow()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> msg = stackalloc byte[1] { 0x01 };
			Span<byte> small = stackalloc byte[CryptoSha512.HashLen - 1];
			CryptoSha512.ComputeHash(small, msg);
		});
	}

	[Test]
	public void ComputeHash512_OversizedHashBuffer_ShouldThrow()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> msg = stackalloc byte[1] { 0x01 };
			Span<byte> large = stackalloc byte[CryptoSha512.HashLen + 1];
			CryptoSha512.ComputeHash(large, msg);
		});
	}

	[Test]
	public void ComputeHash512_NullStream_ShouldThrow()
	{
		AssertLite.Throws<ArgumentNullException>(() =>
		{
			Span<byte> hash = stackalloc byte[CryptoSha512.HashLen];
			Stream? s = null;
			CryptoSha512.ComputeHash(hash, s!);
		});
	}
}

```


