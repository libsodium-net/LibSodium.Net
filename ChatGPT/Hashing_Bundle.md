# 🧩 LibSodium.Net Hashing Bundle

This bundle contains the full source, tests, and guide for:

- `CryptoGenericHash` (BLAKE2b)
- `CryptoShortHash` (SipHash-2-4)
- `CryptoPasswordHash` (Argon2id/i13)
- ✅ With complete test coverage and guide

---

## 📄 Guide: Hashing.md

# 🔀 Hashing

LibSodium.Net provides multiple hashing APIs for different use cases:

| API                  | Algorithm    | Use Case                                                                              |
| -------------------- | ------------ | ------------------------------------------------------------------------------------- |
| `GenericHash`        | BLAKE2b      | Cryptographic hash with optional key. Use for MAC, PRF, fingerprints.                 |
| `ShortHash`          | SipHash‑2‑4  | Keyed hash designed to prevent collisions in hash tables. Fast for short inputs.      |
| `CryptoSha256`       | SHA‑256      | Fast fixed‑length (32‑byte) hash for integrity checks, digital signatures, checksums. |
| `CryptoSha512`       | SHA‑512      | Fast fixed‑length (64‑byte) hash for high‑strength integrity and digital signatures.  |
| `CryptoPasswordHash` | Argon2id/i13 | Password hashing and key derivation (slow & memory‑hard)                              |

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

## ✨ PasswordHash

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
| `InteractiveIterations` | 2              | Iteration count for interactive targets |
| `InteractiveMemoryLen`  | 64 MB          | Memory usage for interactive targets    |
| `SensitiveIterations`   | 4              | Iteration count for sensitive targets   |
| `SensitiveMemoryLen`    | 1 GB           | Memory usage for sensitive targets      |
| `MinMemoryLen`          | 8 KB           | Minimum acceptable memory for hashing   |

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

## ⚠️ Error Handling

* `ArgumentException` — when input or key lengths are invalid
* `ArgumentOutOfRangeException` — when iterations or memory limits are too low
* `LibSodiumException` — if the underlying native function fails

---

## 📝 Notes

* `GenericHash` is based on BLAKE2b and supports variable‑length output and optional keys.
* `CryptoSha256` and `CryptoSha512` provide interoperable SHA‑2 digests and are the best choice when you need a *fixed‑length* checksum or compatibility with external systems.
* `ShortHash` is based on SipHash‑2‑4 — *not* a general‑purpose cryptographic hash, but a keyed primitive for protecting hash tables.
* `CryptoPasswordHash` uses Argon2id/Argon2i13 with computational and memory hardness.
* All hash functions are deterministic: same input and key produce same output — **except** `CryptoPasswordHash.HashPassword`, which includes a random salt and produces a different hash each time.
* Use `ShortHash` only when you can keep the key secret.

---

## 🧭 Choosing the Right Hash API

| Scenario                                                 | Recommended API       |
| -------------------------------------------------------- | --------------------- |
| Variable‑length cryptographic checksum                   | `GenericHash`         |
| Fixed‑length 32‑byte digest (e.g., TLS cert fingerprint) | `CryptoSha256`        |
| Fixed‑length 64‑byte digest, higher speed on x64         | `CryptoSha512`        |
| MAC or PRF                                               | `GenericHash` (keyed) |
| Hashing short keys in tables                             | `ShortHash`           |
| Password storage / passphrase‑derived keys               | `CryptoPasswordHash`  |

## 👀 See Also

* ℹ️ [API Reference: CryptoGenericHash](../api/LibSodium.CryptoGenericHash.yml)
* ℹ️ [API Reference: CryptoSha256](../api/LibSodium.CryptoSha256.yml)
* ℹ️ [API Reference: CryptoSha512](../api/LibSodium.CryptoSha512.yml)
* ℹ️ [API Reference: CryptoShortHash](../api/LibSodium.CryptoShortHash.yml)
* ℹ️ [API Reference: CryptoPasswordHash](../api/LibSodium.CryptoPasswordHash.yml)
* 🧂 [libsodium Hashing](https://doc.libsodium.org/hashing)
* 🧂 [libsodium Password Hashing](https://doc.libsodium.org/password_hashing)
* 🧂 [libsodium SHA-2](https://doc.libsodium.org/advanced/sha-2_hash_function)<br/>


---

## 📦 Source: CryptoGenericHash.cs
```csharp
using LibSodium.Interop;

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
				throw new ArgumentException($"Hash length must be between {MinHashLen} and {MaxHashLen} bytes.", nameof(hash));
			if (key.Length > MaxKeyLen)
				throw new ArgumentException($"Key length must be between 0 and {MaxKeyLen} bytes.", nameof(key));
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
			if (hash.Length < MinHashLen || hash.Length > MaxHashLen)
				throw new ArgumentException($"Hash length must be between {MinHashLen} and {MaxHashLen} bytes.", nameof(hash));
			if (key.Length > MaxKeyLen)
				throw new ArgumentException($"Key length must be between 0 and {MaxKeyLen} bytes.", nameof(key));
			Span<byte> state = stackalloc byte[StateLen];
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_generichash_init(state, key, (nuint)key.Length, (nuint)hash.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");
			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
			{
				result = Native.crypto_generichash_update(state, buffer, (ulong)bytesRead);
				if (result != 0)
					throw new LibSodiumException("Hashing failed.");
			}
			result = Native.crypto_generichash_final(state, hash, (nuint)hash.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");

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
			if (hash.Length < MinHashLen || hash.Length > MaxHashLen)
				throw new ArgumentException($"Hash length must be between {MinHashLen} and {MaxHashLen} bytes.", nameof(hash));
			if (key.Length > MaxKeyLen)
				throw new ArgumentException($"Key length must be between 0 and {MaxKeyLen} bytes.", nameof(key));

			byte[] stateBuffer = new byte[StateLen];
			LibraryInitializer.EnsureInitialized();
			int result = Native.crypto_generichash_init(stateBuffer, key.Span, (nuint)key.Length, (nuint)hash.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");

			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
			{
				result = Native.crypto_generichash_update(stateBuffer, buffer, (ulong) bytesRead);
				if (result != 0)
					throw new LibSodiumException("Hashing failed.");
			}

			result = Native.crypto_generichash_final(stateBuffer, hash.Span, (nuint)hash.Length);
			if (result != 0)
				throw new LibSodiumException("Hashing failed.");
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
using LibSodium.Interop;
using System.Buffers;

namespace LibSodium
{
	/// <summary>
	/// Provides one‑shot and streaming <b>SHA‑256</b> hashing helpers built on libsodium’s
	/// <c>crypto_hash_sha256</c> API.
	/// </summary>
	public static class CryptoSha256
	{
		/// <summary>Hash length in bytes (32).</summary>
		public const int HashLen = Native.CRYPTO_HASH_SHA256_BYTES;

		/// <summary>Size of the internal hashing state structure (implementation‑defined).</summary>
		internal static readonly int StateLen = (int)Native.crypto_hash_sha256_statebytes();

		private const int DefaultBufferSize = 8 * 1024; // 8 KiB


		/// <summary>
		/// Computes a SHA‑256 hash of <paramref name="message"/> and stores the result in
		/// <paramref name="hash"/>.
		/// </summary>
		/// <param name="hash">Destination buffer (32 bytes).</param>
		/// <param name="message">Message to hash.</param>
		/// <exception cref="ArgumentException">If <paramref name="hash"/> length ≠ 32.</exception>
		/// <exception cref="LibSodiumException">If the native function returns non‑zero.</exception>
		public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
		{
			if (hash.Length != HashLen)
				throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_hash_sha256(hash, message, (ulong)message.Length);
			if (rc != 0)
				throw new LibSodiumException("SHA‑256 hashing failed.");
		}

		/// <summary>
		/// Computes a SHA‑256 hash over the entire contents of the supplied <see cref="Stream"/>.
		/// </summary>
		/// <param name="hash">Destination buffer (32 bytes) that receives the final hash.</param>
		/// <param name="input">The input stream to read and hash. The stream is read until its end.</param>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is <c>null</c>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="hash"/> is not exactly 32 bytes.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying libsodium call fails.</exception>
		/// <remarks>
		/// The method processes the stream in buffered chunks of <c>8 KiB</c>, keeping memory usage low even for very large inputs.
		/// </remarks>
		public static void ComputeHash(Span<byte> hash, Stream input)
		{
			ArgumentNullException.ThrowIfNull(input);
			if (hash.Length != HashLen)
				throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));

			Span<byte> state = stackalloc byte[StateLen];
			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_hash_sha256_init(state) != 0)
				throw new LibSodiumException("SHA‑256 init failed.");

			byte[] buffer = ArrayPool<byte>.Shared.Rent(DefaultBufferSize);
			try
			{
				int read;
				while ((read = input.Read(buffer, 0, DefaultBufferSize)) > 0)
				{
					if (Native.crypto_hash_sha256_update(state, buffer, (ulong)read) != 0)
						throw new LibSodiumException("SHA‑256 update failed.");
				}
				if (Native.crypto_hash_sha256_final(state, hash) != 0)
					throw new LibSodiumException("SHA‑256 final failed.");
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
			}
		}

		/// <summary>
		/// Asynchronously computes a SHA‑256 hash over the supplied <see cref="Stream"/>, writing the
		/// result into <paramref name="hash"/>.
		/// </summary>
		/// <param name="hash">Destination memory buffer (32 bytes) that receives the final hash.</param>
		/// <param name="input">The input stream to read and hash. The stream is read until its end.</param>
		/// <param name="cancellationToken">Token that can be used to cancel the asynchronous operation.</param>
		/// <returns>A task that completes when the hash has been fully computed and written.</returns>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is <c>null</c>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="hash"/> is not exactly 32 bytes.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying libsodium call fails.</exception>
		/// <remarks>
		/// The method reads the stream in buffered chunks of <c>8 KiB</c> and is fully asynchronous, making it suitable for
		/// hashing network streams or large files without blocking the calling thread.
		/// </remarks>
		public static async Task ComputeHashAsync(Memory<byte> hash, Stream input, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(input);
			if (hash.Length != HashLen)
				throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));

			byte[] state = new byte[StateLen];
			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_hash_sha256_init(state) != 0)
				throw new LibSodiumException("SHA‑256 init failed.");

			byte[] buffer = ArrayPool<byte>.Shared.Rent(DefaultBufferSize);
			try
			{
				int read;
				while ((read = await input.ReadAsync(buffer, 0, DefaultBufferSize, cancellationToken).ConfigureAwait(false)) > 0)
				{
					if (Native.crypto_hash_sha256_update(state, buffer, (ulong)read) != 0)
						throw new LibSodiumException("SHA‑256 update failed.");
				}
				if (Native.crypto_hash_sha256_final(state, hash.Span) != 0)
					throw new LibSodiumException("SHA‑256 final failed.");
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
			}
		}
	}
}
```
## CryptoSha512 source code

```csharp
using LibSodium.Interop;
using System.Buffers;

namespace LibSodium
{
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
		private const int DefaultBufferSize = 8 * 1024; // 8 KiB

		/// <summary>
		/// Computes a SHA‑512 hash of <paramref name="message"/> and stores the result in
		/// <paramref name="hash"/>.
		/// </summary>
		/// <param name="hash">Destination buffer (64 bytes).</param>
		/// <param name="message">Message to hash.</param>
		/// <exception cref="ArgumentException">If <paramref name="hash"/> length ≠ 64.</exception>
		/// <exception cref="LibSodiumException">If the native function returns non‑zero.</exception>
		public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
		{
			if (hash.Length != HashLen)
				throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_hash_sha512(hash, message, (ulong)message.Length);
			if (rc != 0)
				throw new LibSodiumException("SHA‑512 hashing failed.");
		}

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
		{
			ArgumentNullException.ThrowIfNull(input);
			if (hash.Length != HashLen)
				throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));

			Span<byte> state = stackalloc byte[StateLen];
			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_hash_sha512_init(state) != 0)
				throw new LibSodiumException("SHA‑512 init failed.");

			byte[] buffer = ArrayPool<byte>.Shared.Rent(DefaultBufferSize);
			try
			{
				int read;
				while ((read = input.Read(buffer, 0, DefaultBufferSize)) > 0)
				{
					if (Native.crypto_hash_sha512_update(state, buffer, (ulong)read) != 0)
						throw new LibSodiumException("SHA‑512 update failed.");
				}
				if (Native.crypto_hash_sha512_final(state, hash) != 0)
					throw new LibSodiumException("SHA‑512 final failed.");
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
			}
		}

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
		{
			ArgumentNullException.ThrowIfNull(input);
			if (hash.Length != HashLen)
				throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));

			byte[] state = new byte[StateLen];
			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_hash_sha512_init(state) != 0)
				throw new LibSodiumException("SHA‑512 init failed.");

			byte[] buffer = ArrayPool<byte>.Shared.Rent(DefaultBufferSize);
			try
			{
				int read;
				while ((read = await input.ReadAsync(buffer, 0, DefaultBufferSize, cancellationToken).ConfigureAwait(false)) > 0)
				{
					if (Native.crypto_hash_sha512_update(state, buffer, (ulong)read) != 0)
						throw new LibSodiumException("SHA‑512 update failed.");
				}
				if (Native.crypto_hash_sha512_final(state, hash.Span) != 0)
					throw new LibSodiumException("SHA‑512 final failed.");
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
			}
		}
	}
}
```




