# 🔑 Key Derivation in LibSodium.Net

LibSodium.Net provides two powerful primitives for key derivation:

* `CryptoKeyDerivation`: libsodium's native KDF built on BLAKE2b.
* `Hkdf`: a standard HKDF implementation based on HMAC (SHA-256 or SHA-512).

>🧂 Based on libsodium's [Key derivation](https://doc.libsodium.org/key_derivation)<br/>
>🧂 Based on libsodium's [HKDF](https://doc.libsodium.org/key_derivation/hkdf)<br/>
> ℹ️ *See also*: [API Reference for `CryptoKeyDerivation`](../api/LibSodium.CryptoKeyDerivation.yml)<br/>
> ℹ️ *See also*: [API Reference for `HKDF`](../api/LibSodium.HKDF.yml)

This guide compares both options, shows how to choose between them, and offers practical usage advice.

---

## 📋 Overview of Alternatives

| Feature          | `CryptoKeyDerivation`        | `Hkdf`                            |
| ---------------- | ---------------------------- | --------------------------------- |
| Algorithm        | BLAKE2b                      | HMAC-SHA-256 / HMAC-SHA-512       |
| Based on         | `crypto_kdf_*` API           | `crypto_kdf_hkdf_{sha256,sha512}` |
| Standard         | No                           | RFC 5869                          |
| Derivation style | Single-step                  | Extract-then-expand               |
| Inputs           | masterKey, subkeyId, context | ikm, salt, info                   |
| Deterministic    | Yes                          | Yes                               |
| Performance      | Faster                       | Slower                            |
| Interoperability | Low                          | High                              |

---

## ⚙️ Practical Differences

### Subkey Identifier and State

| Characteristic             | `CryptoKeyDerivation`               | `Hkdf`                                |
| -------------------------- | ----------------------------------- | ------------------------------------- |
| Subkey uniqueness driver   | `ulong subkeyId` + 8-byte `context` | Arbitrary `salt` and `info`           |
| Max identifier size        | 16 bytes total (id + context)       | Arbitrary                             |
| Collisions with random IDs | Realistic risk                      | Practically zero (if inputs are long) |
| State requirement          | Yes (track last subkeyId)           | No                                    |
| Stateless randomness       | Not safe                            | Safe                                  |
| Best practice              | Use a database sequence             | Use long random salt/info             |

### Performance

* `CryptoKeyDerivation` is faster due to BLAKE2b.
* `HKDF` (especially SHA-512) is slower but widely standardized.

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

---

## 🧭 Recommendation

Use `HKDF` (preferably SHA-512) by default unless you have a controlled use case requiring deterministic subkey sequences with high performance.

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

```csharp
Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
CryptoKeyDerivation.GenerateMasterKey(masterKey);
```

### 📋 Derive a subkey

```csharp
Span<byte> subkey = stackalloc byte[32];
CryptoKeyDerivation.DeriveSubkey(subkey, 42, "MYCTX", masterKey);
```

📝 Context must be exactly 8 bytes. Strings shorter than 8 are zero-padded.

---

## ✨ `HKDF`

`HKDF` implements RFC 5869 using HMAC-SHA-256 or HMAC-SHA-512. It is compatible with `System.Security.Cryptography.HKDF.DeriveKey` and produces identical outputs when the inputs match.

📝 LibSodium.Net's `HKDF` is fully interoperable with `System.Security.Cryptography.HKDF` from .NET — both produce identical outputs when using the same inputs and hash algorithm.

### 📏 Constants

| Name        | SHA256 | SHA512 | Description                              |
| ----------- | ------ | ------ | ---------------------------------------- |
| `PrkLen`    | 32     | 64     | Length of PRK (pseudorandom key)         |
| `MinOkmLen` | 4      | 4      | Minimum output length                    |
| `MaxOkmLen` | 8160   | 16320  | Maximum output length (255 \* hash size) |

### 🪄 HKDF Phases

* `Extract`: converts input keying material (IKM) and salt into a pseudorandom key (PRK).
* `Expand`: derives the final output key material (OKM) from the PRK and optional `info`.
* `DeriveKey`: performs both steps in one call.

#### When to use which:

* Use `DeriveKey` for simple cases where no reuse of PRK is needed.
* Use `Extract` + `Expand` when you want to reuse PRK for multiple outputs.
* Use `Expand` when you already have a good master key.

### 📋 Derive a key in one step

```csharp
Span<byte> key = stackalloc byte[64];
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

This allows deriving a PRK from streamed IKM's.

```csharp
using var stream = File.OpenRead("large-secret.bin");
Span<byte> prk = stackalloc byte[HKDF.Sha512PrkLen];
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

---

## 👀 See Also

* [libsodium key derivation](https://doc.libsodium.org/key_derivation)
* [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
* [API Reference: CryptoKeyDerivation](../api/LibSodium.CryptoKeyDerivation.yml)
* [API Reference: HKDF](../api/LibSodium.HKDF.yml)

## CryptoKeyDerivation.cs Native

```csharp
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		public const string CRYPTO_KDF_PRIMITIVE = "blake2b";
		public const int CRYPTO_KDF_BYTES_MIN = 16;
		public const int CRYPTO_KDF_BYTES_MAX = 64;
		public const int CRYPTO_KDF_CONTEXTBYTES = 8;
		public const int CRYPTO_KDF_KEYBYTES = 32;

		/// <summary>
		/// Generates a random master key for use with crypto_kdf_derive_from_key.
		/// </summary>
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_keygen))]
		internal static partial void crypto_kdf_keygen(Span<byte> key);

		/// <summary>
		/// Derives a subkey from a master key.
		/// </summary>
		/// <param name="subkey">Output buffer for the derived subkey.</param>
		/// <param name="subkeyLen">Length of the subkey to derive.</param>
		/// <param name="subkeyId">Unique identifier for the subkey.</param>
		/// <param name="context">8-byte context string to namespace subkeys.</param>
		/// <param name="masterKey">The 32-byte master key.</param>
		/// <returns>0 on success, -1 on failure.</returns>
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_derive_from_key))]
		internal static partial int crypto_kdf_derive_from_key(
			Span<byte> subkey,
			nuint subkeyLen,
			ulong subkeyId,
			ReadOnlySpan<byte> context,
			ReadOnlySpan<byte> masterKey);
	}
}

```

## CryptoKeyDerivation.cs API

```csharp
using System;
using System.Text;
using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides deterministic key derivation using libsodium's crypto_kdf_* API,
	/// based on the BLAKE2b hash function.
	/// </summary>
	public static class CryptoKeyDerivation
	{
		/// <summary>
		/// Length of the master key in bytes (32).
		/// </summary>
		public const int MasterKeyLen = Native.CRYPTO_KDF_KEYBYTES;

		/// <summary>
		/// Minimum length of a derived subkey (16).
		/// </summary>
		public const int MinSubkeyLen = Native.CRYPTO_KDF_BYTES_MIN;

		/// <summary>
		/// Maximum length of a derived subkey (64).
		/// </summary>
		public const int MaxSubkeyLen = Native.CRYPTO_KDF_BYTES_MAX;

		/// <summary>
		/// Length of the context in bytes (8).
		/// </summary>
		public const int ContextLen = Native.CRYPTO_KDF_CONTEXTBYTES;

		/// <summary>
		/// Fills the given buffer with a new random master key (32 bytes).
		/// </summary>
		/// <param name="masterKey">The buffer to fill. Must be 32 bytes.</param>
		/// <exception cref="ArgumentException">Thrown when <paramref name="masterKey"/> is not 32 bytes.</exception>
		public static void GenerateMasterKey(Span<byte> masterKey)
		{
			if (masterKey.Length != MasterKeyLen)
				throw new ArgumentException($"Master key must be {MasterKeyLen} bytes long.", nameof(masterKey));
			LibraryInitializer.EnsureInitialized();
			Native.crypto_kdf_keygen(masterKey);
		}

		/// <summary>
		/// Deterministically derives a subkey from a master key, context, and subkey ID.
		/// Uses the BLAKE2b hash function internally.
		/// </summary>
		/// <param name="subkey">The buffer where the derived subkey will be written. Its length must be between 16 and 64 bytes.</param>
		/// <param name="subkeyId">The identifier for the subkey (application-defined).</param>
		/// <param name="context">8-byte context describing the usage.</param>
		/// <param name="masterKey">The master key (32 bytes).</param>
		/// <exception cref="ArgumentException">
		/// Thrown when <paramref name="subkey"/> is out of bounds, <paramref name="context"/> is not 8 bytes,
		/// or <paramref name="masterKey"/> is not 32 bytes.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the native key derivation fails.</exception>
		public static void DeriveSubkey(
			Span<byte> subkey,
			ulong subkeyId,
			ReadOnlySpan<byte> context,
			ReadOnlySpan<byte> masterKey)
		{
			if (subkey.Length < MinSubkeyLen || subkey.Length > MaxSubkeyLen)
				throw new ArgumentException($"Subkey length must be between {MinSubkeyLen} and {MaxSubkeyLen} bytes.", nameof(subkey));

			if (context.Length != ContextLen)
				throw new ArgumentException($"Context must be exactly {ContextLen} bytes.", nameof(context));

			if (masterKey.Length != MasterKeyLen)
				throw new ArgumentException($"Master key must be {MasterKeyLen} bytes.", nameof(masterKey));
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_kdf_derive_from_key(subkey, (nuint)subkey.Length, subkeyId, context, masterKey);
			if (rc != 0)
				throw new LibSodiumException("Key derivation failed.");
		}

		/// <summary>
		/// Deterministically derives a subkey from a master key, using a context string whose UTF-8 representation is at most 8 bytes,
		/// and a subkey ID. If the string is shorter, it is padded with zeros. Uses the BLAKE2b hash function internally.
		/// </summary>
		/// <param name="subkey">The buffer where the derived subkey will be written. Its length must be between 16 and 64 bytes.</param>
		/// <param name="subkeyId">The identifier for the subkey (application-defined).</param>
		/// <param name="context">A string whose UTF-8 representation must be at most 8 bytes and describes the usage context.</param>
		/// <param name="masterKey">The master key (32 bytes).</param>
		/// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
		/// <exception cref="ArgumentException">
		/// Thrown when <paramref name="context"/> exceeds 8 UTF-8 bytes,
		/// or <paramref name="subkey"/> or <paramref name="masterKey"/> are of invalid length.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the native key derivation fails.</exception>
		public static void DeriveSubkey(
			Span<byte> subkey,
			ulong subkeyId,
			string context,
			ReadOnlySpan<byte> masterKey)
		{
			ArgumentNullException.ThrowIfNull(context);

			Span<byte> utf8Context = stackalloc byte[ContextLen];
			try
			{
				Encoding.UTF8.GetBytes(context, utf8Context);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException($"Context must be a UTF-8 representable string of at most {ContextLen} bytes.", nameof(context), ex);
			}

			DeriveSubkey(subkey, subkeyId, utf8Context, masterKey);
		}
	}
}
```

## HKDF.cs Native

```csharp
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		public const int CRYPTO_KDF_HKDF_SHA256_KEYBYTES = 32;
		public const int CRYPTO_KDF_HKDF_SHA256_BYTES_MIN = 0;
		public const int CRYPTO_KDF_HKDF_SHA256_BYTES_MAX = 8160;

		public const int CRYPTO_KDF_HKDF_SHA512_KEYBYTES = 64;
		public const int CRYPTO_KDF_HKDF_SHA512_BYTES_MIN = 0;
		public const int CRYPTO_KDF_HKDF_SHA512_BYTES_MAX = 16320;

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_extract))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha256_extract(
			Span<byte> prk,
			ReadOnlySpan<byte> salt,
			nuint salt_len,
			ReadOnlySpan<byte> ikm,
			nuint ikm_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_expand))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha256_expand(
			Span<byte> okm,
			nuint okm_len,
			ReadOnlySpan<byte> info,
			nuint info_len,
			ReadOnlySpan<byte> prk);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_extract))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha512_extract(
			Span<byte> prk,
			ReadOnlySpan<byte> salt,
			nuint saltLen,
			ReadOnlySpan<byte> ikm,
			nuint ikmLen);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_expand))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha512_expand(
			Span<byte> okm,
			nuint okmLen,
			ReadOnlySpan<byte> info,
			nuint infoLen,
			ReadOnlySpan<byte> prk);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial nuint crypto_kdf_hkdf_sha256_statebytes();

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_statebytes))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial nuint crypto_kdf_hkdf_sha512_statebytes();

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_extract_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha256_extract_init(
			Span<byte> state,
			ReadOnlySpan<byte> salt,
			nuint salt_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_extract_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha256_extract_update(
			Span<byte> state,
			ReadOnlySpan<byte> ikm,
			nuint ikm_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha256_extract_final))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha256_extract_final(
			Span<byte> state,
			Span<byte> prk);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_extract_init))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha512_extract_init(
			Span<byte> state,
			ReadOnlySpan<byte> salt,
			nuint salt_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_extract_update))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha512_extract_update(
			Span<byte> state,
			ReadOnlySpan<byte> ikm,
			nuint ikm_len);

		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_hkdf_sha512_extract_final))]
		[UnmanagedCallConv(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
		internal static partial int crypto_kdf_hkdf_sha512_extract_final(
			Span<byte> state,
			Span<byte> prk);
	}
}
```

## HKDF.cs API

```csharp
using System.Security.Cryptography;
using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides HKDF key derivation (RFC 5869) using SHA-256 or SHA-512.
	/// </summary>
	public static class HKDF
	{
		/// <summary>
		/// Length of the pseudorandom key (PRK) for SHA256 in bytes (32).
		/// </summary>
		public const int Sha256PrkLen = 32;

		/// <summary>
		/// Length of the pseudorandom key (PRK) for SHA256 in bytes (32).
		/// </summary>
		public const int Sha512PrkLen = 64;

		/// <summary>
		/// Minimum length of output key material (OKM) in bytes (4).
		/// </summary>
		public const int MinOkmLen = 4;

		/// <summary>
		/// Maximum length of output key material (OKM) for SHA256 in bytes (8160 = 32 * 255).
		/// </summary>
		public const int Sha256MaxOkmLen = 8160;

		/// <summary>
		/// Maximum length of output key material (OKM) for SHA512 in bytes (8160 = 64 * 255).
		/// </summary>
		public const int Sha512MaxOkmLen = 16320;


		internal static readonly int Sha256StateLen = (int)Native.crypto_kdf_hkdf_sha256_statebytes();
		internal static readonly int Sha512StateLen = (int)Native.crypto_kdf_hkdf_sha512_statebytes();

		private static int FillBuffer(Stream stream, byte[] buffer, int offset, int count)
		{
			int totalRead = 0;
			while (totalRead < count)
			{
				int read = stream.Read(buffer, offset + totalRead, count - totalRead);
				if (read == 0)
					break; // EOF
				totalRead += read;
			}
			return totalRead;
		}

		private static async Task<int> FillBufferAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
		{
			int totalRead = 0;
			while (totalRead < count)
			{
				int read = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead, ct).ConfigureAwait(false);
				if (read == 0)
					break; // EOF
				totalRead += read;
			}
			return totalRead;
		}

		/// <summary>
		/// Performs the extract step of HKDF (RFC 5869), using the specified hash algorithm.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Input keying material.</param>
		/// <param name="salt">Optional salt value (can be empty).</param>
		/// <param name="prk">Buffer to receive the pseudorandom key (32 bytes for SHA256 and 64 bytes for SHA512).</param>
		/// <exception cref="ArgumentException">Thrown if <paramref name="prk"/> is not exactly the required size.</exception>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>
		public static void Extract(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, Span<byte> prk)
		{
			int result = 0;
			switch (hashAlgorithmName.Name)
			{
				case nameof(HashAlgorithmName.SHA256):
					if (prk.Length != Sha256PrkLen) throw new ArgumentException($"PRK buffer must be exactly {Sha256PrkLen} bytes for SHA256.", nameof(prk));
					LibraryInitializer.EnsureInitialized();
					result = Native.crypto_kdf_hkdf_sha256_extract(prk, salt, (nuint)salt.Length, ikm, (nuint)ikm.Length); break;

				case nameof(HashAlgorithmName.SHA512):
					if (prk.Length != Sha512PrkLen) throw new ArgumentException($"PRK buffer must be exactly {Sha512PrkLen} bytes for SHA512.", nameof(prk));
					LibraryInitializer.EnsureInitialized();
					result = Native.crypto_kdf_hkdf_sha512_extract(prk, salt, (nuint)salt.Length, ikm, (nuint)ikm.Length); break;
				default:
					throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}");

			}
			if (result != 0)
				throw new LibSodiumException($"Failed to extract prk using hash algorithm {hashAlgorithmName.Name}");
		}

		/// <summary>
		/// Performs the expand step of HKDF (RFC 5869), using the specified hash algorithm.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="prk">Pseudorandom key obtained from the extract step (32 or 64 bytes).</param>
		/// <param name="okm">Output buffer to receive the derived keying material (4–8160 or 16320 bytes).</param>
		/// <param name="info">Optional context and application-specific information.</param>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="okm"/> is not in valid range.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="prk"/> is not valid size for the selected hash.</exception>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>
		public static void Expand(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> prk, Span<byte> okm, ReadOnlySpan<byte> info)
		{
			int result = 0;
			switch (hashAlgorithmName.Name)
			{
				case nameof(HashAlgorithmName.SHA256):
					if (okm.Length < MinOkmLen || okm.Length > Sha256MaxOkmLen)
						throw new ArgumentOutOfRangeException(nameof(okm), $"Output length must be between {MinOkmLen} and {Sha256MaxOkmLen} bytes for SHA256.");
					if (prk.Length != Sha256PrkLen)
						throw new ArgumentException($"PRK must be exactly {Sha256PrkLen} bytes for SHA256.", nameof(prk));
					LibraryInitializer.EnsureInitialized();
					result = Native.crypto_kdf_hkdf_sha256_expand(okm, (nuint)okm.Length, info, (nuint)info.Length, prk);
					break;
				case nameof(HashAlgorithmName.SHA512):
					if (okm.Length < MinOkmLen || okm.Length > Sha512MaxOkmLen)
						throw new ArgumentOutOfRangeException(nameof(okm), $"Output length must be between {MinOkmLen} and {Sha512MaxOkmLen} bytes for SHA512.");
					if (prk.Length != Sha512PrkLen)
						throw new ArgumentException($"PRK must be exactly {Sha512PrkLen} bytes for SHA512.", nameof(prk));
					LibraryInitializer.EnsureInitialized();
					result = Native.crypto_kdf_hkdf_sha512_expand(okm, (nuint)okm.Length, info, (nuint)info.Length, prk);
					break;
				default:
					throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}");
			}
			if (result != 0)
				throw new LibSodiumException($"Failed to expand using hash algorithm {hashAlgorithmName.Name}");
		}

		/// <summary>
		/// Derives key material from input key material in one step using HKDF (RFC 5869).
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Input keying material.</param>
		/// <param name="okm">Output buffer to receive the derived keying material (16–64 bytes).</param>
		/// <param name="salt">Optional salt value (can be empty).</param>
		/// <param name="info">Optional context and application-specific information.</param>
		/// <exception cref="ArgumentException">Thrown if <paramref name="okm"/> or internal buffers have invalid lengths.</exception>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>
		public static void DeriveKey(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> ikm, Span<byte> okm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
		{
			var prkLen = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Sha256PrkLen,
				nameof(HashAlgorithmName.SHA512) => Sha512PrkLen,
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};
			Span<byte> prk = stackalloc byte[prkLen];
			Extract(hashAlgorithmName, ikm, salt, prk);
			Expand(hashAlgorithmName, prk, okm, info);
		}

		/// <summary>
		/// Performs the extract step of HKDF (RFC 5869) using a stream as input keying material.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Stream of input keying material (IKM).</param>
		/// <param name="salt">Optional salt value (can be empty).</param>
		/// <param name="prk">Buffer to receive the pseudorandom key (32 bytes for SHA256 and 64 bytes for SHA512).</param>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="ikm"/> is null.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="prk"/> length is incorrect.</exception>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>
		public static void Extract(HashAlgorithmName hashAlgorithmName, Stream ikm, ReadOnlySpan<byte> salt, Span<byte> prk)
		{
			if (ikm == null) throw new ArgumentNullException(nameof(ikm));

			Span<byte> state = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => stackalloc byte[Sha256StateLen],
				nameof(HashAlgorithmName.SHA512) => stackalloc byte[Sha512StateLen],
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			int result;
			LibraryInitializer.EnsureInitialized();

			result = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_init(state, salt, (nuint)salt.Length),
				nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_init(state, salt, (nuint)salt.Length),
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			if (result != 0)
				throw new LibSodiumException($"Failed to initialize extract state for {hashAlgorithmName.Name}");

			byte[] buffer = new byte[4096];
			int read;
			while ((read = FillBuffer(ikm, buffer, 0, buffer.Length)) > 0)
			{
				Span<byte> chunk = buffer.AsSpan(0, read);
				result = hashAlgorithmName.Name switch
				{
					nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_update(state, chunk, (nuint)chunk.Length),
					nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_update(state, chunk, (nuint)chunk.Length),
					_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
				};
				if (result != 0)
					throw new LibSodiumException($"Failed to update extract state for {hashAlgorithmName.Name}");
			}

			result = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_final(state, prk),
				nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_final(state, prk),
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			if (result != 0)
				throw new LibSodiumException($"Failed to finalize extract for {hashAlgorithmName.Name}");
		}

		/// <summary>
		/// Asynchronously performs the extract step of HKDF (RFC 5869) using a stream as input keying material.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Stream of input keying material (IKM).</param>
		/// <param name="salt">Optional salt value (can be empty).</param>
		/// <param name="prk">Buffer to receive the pseudorandom key (32 bytes for SHA256 and 64 bytes for SHA512).</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="ikm"/> is null.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="prk"/> length is incorrect.</exception>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>

		public static async Task ExtractAsync(HashAlgorithmName hashAlgorithmName, Stream ikm, ReadOnlyMemory<byte> salt, Memory<byte> prk, CancellationToken cancellationToken = default)
		{
			if (ikm == null) throw new ArgumentNullException(nameof(ikm));

			var state = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => new byte[Sha256StateLen],
				nameof(HashAlgorithmName.SHA512) => new byte[Sha512StateLen],
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			int result;
			LibraryInitializer.EnsureInitialized();

			result = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_init(state, salt.Span, (nuint)salt.Length),
				nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_init(state, salt.Span, (nuint)salt.Length),
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			if (result != 0)
				throw new LibSodiumException($"Failed to initialize extract state for {hashAlgorithmName.Name}");

			byte[] buffer = new byte[4096];
			int read;
			while ((read = await FillBufferAsync(ikm, buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
			{
				result = hashAlgorithmName.Name switch
				{
					nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_update(state, buffer.AsSpan(0, read), (nuint)read),
					nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_update(state, buffer.AsSpan(0, read), (nuint)read),
					_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
				};
				if (result != 0)
					throw new LibSodiumException($"Failed to update extract state for {hashAlgorithmName.Name}");
			}

			result = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Native.crypto_kdf_hkdf_sha256_extract_final(state, prk.Span),
				nameof(HashAlgorithmName.SHA512) => Native.crypto_kdf_hkdf_sha512_extract_final(state, prk.Span),
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};

			if (result != 0)
				throw new LibSodiumException($"Failed to finalize extract for {hashAlgorithmName.Name}");
		}

		/// <summary>
		/// Derives key material from input key material in one step using HKDF (RFC 5869) from a stream.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Stream of input keying material.</param>
		/// <param name="okm">Buffer to receive the output keying material.</param>
		/// <param name="salt">Optional salt value.</param>
		/// <param name="info">Optional application-specific information.</param>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>

		public static void DeriveKey(HashAlgorithmName hashAlgorithmName, Stream ikm, Span<byte> okm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
		{
			var prkLen = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Sha256PrkLen,
				nameof(HashAlgorithmName.SHA512) => Sha512PrkLen,
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};
			Span<byte> prk = stackalloc byte[prkLen];
			Extract(hashAlgorithmName, ikm, salt, prk);
			Expand(hashAlgorithmName, prk, okm, info);
		}

		/// <summary>
		/// Asynchronously derives key material from input key material in one step using HKDF (RFC 5869) from a stream.
		/// </summary>
		/// <param name="hashAlgorithmName">Hash algorithm to use (SHA-256 or SHA-512).</param>
		/// <param name="ikm">Stream of input keying material.</param>
		/// <param name="okm">Buffer to receive the output keying material.</param>
		/// <param name="salt">Optional salt value.</param>
		/// <param name="info">Optional application-specific information.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <exception cref="NotSupportedException">Thrown if the hash algorithm is unsupported.</exception>
		/// <exception cref="LibSodiumException">Thrown if the underlying native call fails.</exception>
		public static async Task DeriveKeyAsync(HashAlgorithmName hashAlgorithmName, Stream ikm, Memory<byte> okm, ReadOnlyMemory<byte> salt, ReadOnlyMemory<byte> info, CancellationToken cancellationToken = default)
		{
			int prkLen = hashAlgorithmName.Name switch
			{
				nameof(HashAlgorithmName.SHA256) => Sha256PrkLen,
				nameof(HashAlgorithmName.SHA512) => Sha512PrkLen,
				_ => throw new NotSupportedException($"Unsupported hash algorithm: {hashAlgorithmName.Name}")
			};
			var prk = new byte[prkLen];
			await ExtractAsync(hashAlgorithmName, ikm, salt, prk, cancellationToken).ConfigureAwait(false);
			Expand(hashAlgorithmName, prk, okm.Span, info.Span);
		}
	}
}
```
