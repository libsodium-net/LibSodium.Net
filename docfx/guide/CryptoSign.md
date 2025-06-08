## 📜 CryptoSign — Digital Signatures

`CryptoSign` provides functions to digitally sign and verify messages using the **Ed25519** signature scheme.
It produces compact, fixed-size signatures (64 bytes) that allow verifying the authenticity and integrity of a message without encryption.

This is ideal for use cases such as:

* Validating messages or files from trusted sources
* Verifying software updates or configuration payloads
* Authenticating data across systems without requiring secrecy

> 🧂 Based on libsodium [Public-key signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)<br/>
> ℹ️ [API Reference for `CryptoSign`](../api/LibSodium.CryptoSign.yml)

The signing process uses a **private key** (64 bytes), and the verification process only requires the corresponding **public key** (32 bytes).
Messages can be signed in a single call or progressively using a streaming interface for large inputs.

> ⚠️ **Note:** Libsodium provides two related but incompatible algorithms:
>
> * `Sign` and `Verify` use **Ed25519**, signing the full message directly.
> * `PreHashSign` and `PreHashVerify` use **Ed25519ph**, signing a SHA-512 hash of the message.<br/>
>
> 🤔  **You must use matching methods for signing and verification — mixing them will fail.**

## 🌟 Features

* Digital signatures with Ed25519
* Span-based APIs for efficient, allocation-free usage
* Conversion from Ed25519 keys to Curve25519.
* Streaming interface.
* Keys can be provided as `SecureMemory<byte>`, `Span<byte>`/`ReadOnlySpan<byte>`, and `byte[]`.


## 📏 Constants

| Name            | Value | Description                       |
| --------------- | ----- | --------------------------------- |
| `PublicKeyLen`  | 32    | Ed25519 public key length         |
| `PrivateKeyLen` | 64    | Ed25519 private key length        |
| `SignatureLen`  | 64    | Signature length                  |
| `SeedLen`       | 32    | Seed length for deterministic key |

## 📋 Working with CryptoSign

**Generate random key pair:**

```csharp
// SecureMemory
Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeyLen];
using var privateKey = new SecureMemory<byte>(CryptoSign.PrivateKeyLen);
CryptoSign.GenerateKeyPair(publicKey, privateKey);
privateKey.ProtectReadOnly();
```

```csharp
// Span
Span<byte> publicKey = stackalloc byte[CryptoSign.PublicKeyLen];
Span<byte> privateKey = stackalloc byte[CryptoSign.PrivateKeyLen];
CryptoSign.GenerateKeyPair(publicKey, privateKey);
```

**Sign and Verify:**

```csharp
Span<byte> signature = stackalloc byte[CryptoSign.SignatureLen];
CryptoSign.Sign(message, signature, privateKey);

bool ok = CryptoSign.TryVerify(message, signature, publicKey);
CryptoSign.Verify(message, signature, publicKey); // throws LibSodiumException if the signature is invalid
```

## 📋 Signing and Verifying Streams

The `CryptoSign` API also supports signing and verifying large messages using a streaming interface.
This uses the `Ed25519ph` algorithm, which **is not compatible** with standard Ed25519 signatures.

> ⚠️ `PreHashSign` and `PreHashVerify` use the Ed25519ph algorithm.
> These signatures **cannot** be verified using `Verify`, and vice versa.
> Always match signing and verification methods accordingly.

📏 Signature format and key sizes are the same (`64-byte` signature, `32-byte` public key, `64-byte` private key).
But **internally they operate differently**: Ed25519 signs the raw message; Ed25519ph signs a hash of the message.

---

**Sign and verify a stream (sync):**

```csharp
var pk = new byte[CryptoSign.PublicKeyLen];
using var sk = new SecureMemory<byte>(CryptoSign.PrivateKeyLen);
CryptoSign.GenerateKeyPair(pk, sk);

byte[] signature = new byte[CryptoSign.SignatureLen];

using var stream = new MemoryStream();
var message = new byte[256];
Random.Shared.NextBytes(message);
stream.Write(message);
stream.Position = 0;

CryptoSign.PreHashSign(stream, signature, sk);
stream.Position = 0;

bool isValid = CryptoSign.PreHashVerify(stream, signature, pk);
```

---

**Sign and verify a stream (async)**:

```csharp
var pk = new byte[CryptoSign.PublicKeyLen];
using var sk = new SecureMemory<byte>(CryptoSign.PrivateKeyLen);
CryptoSign.GenerateKeyPair(pk, sk);

byte[] signature = new byte[CryptoSign.SignatureLen];

using var stream = new MemoryStream();
var message = new byte[256];
Random.Shared.NextBytes(message);
stream.Write(message);
stream.Position = 0;

await CryptoSign.PreHashSignAsync(stream, signature, sk);
stream.Position = 0;

bool isValid = await CryptoSign.PreHashVerifyAsync(stream, signature, pk);
```


## 📋 Convert Ed25519 to Curve25519

`CryptoSign` allows converting Ed25519 key pairs to Curve25519 format, suitable for encryption and key exchange.

These converted keys can be used with the `CryptoBox` and `CryptoKeyExchange` APIs.

```csharp
// SecureMemory
Span<byte> edPk = stackalloc byte[CryptoSign.PublicKeyLen];
using var edSk = new SecureMemory<byte>(CryptoSign.PrivateKeyLen);
CryptoSign.GenerateKeyPair(edPk, edSk);
edSk.ProtectReadOnly();

Span<byte> curvePk = stackalloc byte[CryptoBox.PublicKeyLen];
using var curveSk = SecureMemory<byte>(CryptoBox.PrivateKeyLen);
CryptoSign.PublicKeyToCurve(curvePk, edPk);
CryptoSign.PrivateKeyToCurve(curveSk, edSk);
curveSk.ProtectReadOnly();
```

```csharp
// Span
Span<byte> edPk = stackalloc byte[CryptoSign.PublicKeyLen];
Span<byte> edSk = stackalloc byte[CryptoSign.PrivateKeyLen];
CryptoSign.GenerateKeyPair(edPk, edSk);

Span<byte> curvePk = stackalloc byte[CryptoBox.PublicKeyLen];
Span<byte> curveSk = stackalloc byte[CryptoBox.PrivateKeyLen];
CryptoSign.PublicKeyToCurve(curvePk, edPk);
CryptoSign.PrivateKeyToCurve(curveSk, edSk);
```

The resulting `curvePk` and `curveSk` can be used anywhere a Curve25519 key is expected.

## ⚠️ Error Handling

- `ArgumentException` — when input buffers have incorrect lengths or invalid parameters.
- `LibSodiumException` — when a crypto operation cannot complete.

## 📝 Notes

- Ed25519 keys are *not* compatible with Curve25519 APIs like `CryptoBox` or `CryptoKeyExchange` — use `PublicKeyToCurve` and `PrivateKeyToCurve` to convert them.
- Ed25519 private keys must be 64 bytes long in libsodium’s format.
- Signatures are deterministic and always 64 bytes long.
- `Verify()` throws on failure, while `TryVerify()` returns `false`.
- The same message signed with the same key always produces the same signature.
- This API is suitable for authentication and non-repudiation, **not for encryption**.
- `Sign` and `PreHashSign` use different algorithms:

  - `Sign` → **Ed25519**: deterministic signature over the full message.
  - `PreHashSign` → **Ed25519ph**: signs a SHA-512 hash of the message.
- These formats are **not interchangeable** — you must verify with the corresponding method.
- The streaming interface is recommended for large messages or when reading from `Stream`.


## 👀 See Also

* [API Reference: CryptoSign](../api/LibSodium.CryptoSign.yml)
* [libsodium Public-key signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)