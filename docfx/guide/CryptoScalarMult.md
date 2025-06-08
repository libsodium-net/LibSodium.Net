# 🔢 Scalar Multiplication with CryptoScalarMult

The `CryptoScalarMult` API exposes the low-level scalar multiplication primitive `crypto_scalarmult`, based on Curve25519.
This operation implements the **X25519** algorithm (ECDH over Curve25519), as defined in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).
It forms the foundation of key exchange protocols such as `CryptoBox`, `CryptoKeyExchange`, and others.

This API is rarely needed directly. It is recommended only when implementing custom protocols or interoperating with other systems that use raw X25519 as defined in RFC 7748.


> 🧂 Based on libsodium's [Scalar multiplication](https://doc.libsodium.org/advanced/scalar_multiplication)<br/>
> ℹ️ [API Reference for `CryptoScalarMult`](../api/LibSodium.CryptoScalarMult.yml)

---

## 🌟 Features

* Curve25519 scalar multiplication (X25519, RFC 7748)
* Directional operation: `Q = n·P`
* Safe public key calculation: `P = n·B`
* Deterministic, constant-time implementation
* Fully allocation-free and Span-friendly
* Used internally by `CryptoBox`, `CryptoKeyExchange`

---

## 📏 Constants

| Name              | Value | Description                         |
| ----------------- | ----- | ------------------------------------|
| `PublicKeyLen`    | 32    | Length of the public key (q = n·B)  |
| `PrivateKeyLen`   | 32    | Length of the private scalar        |
| `SharedPointLen`  | 32    | Length of the computed q = n·P      |

---

## 📋 Working with CryptoScalarMult

**Calculate Public Key:**

Computes the public key `P = n·B` given a private scalar `n` and the curve25519 base point `B`:

```csharp
using var privateKey = new SecureMemory<byte>(CryptoScalarMult.PrivateKeyLen);
Span<byte> publicKey = stackalloc byte[CryptoScalarMult.PublicKeyLen];
RandomGenerator.Fill(privateKey);
CryptoScalarMult.CalculatePublicKey(publicKey, privateKey);
```
---
**Compute Shared Point:**

Performs scalar multiplication `S₁ = n₁·P₂` with a private scalar and a peer’s public key to compute a shared secret point:

```csharp
using var sharedPoint = new SecureMemory(CryptoScalarMult.SharedPointLen);
CryptoScalarMult.Compute(sharedPoint, myPrivateKey, peerPublicKey);
```
---

### ❓ Why Both Parties Compute the Same Shared Secret Point

Let:

* `n₁`: Alice's private scalar key
* `n₂`: Bob's private scalar key

Public keys are calculated by multiplying the private scalar with the base point `B` of the Curve25519:

* Alice's public key: `P₁ = n₁ · B`
* Bob's public key: `P₂ = n₂ · B`

Now both Alice and Bob compute the shared secret by multiplying their private key with the public key of the other party:

```text
S₁ = n₁ · P₂ = n₁ · (n₂ · B) = (n₁ × n₂) · B
S₂ = n₂ · P₁ = n₂ · (n₁ · B) = (n₂ × n₁) · B = (n₁ × n₂) · B = S₁
```

They arrive at the same point because of the algebraic properties of scalar and integer multiplication.  
Particularly, scalar multiplication is **associative** and integer multiplication is **commutative**.  
Therefore, `S₁ = S₂`, and both parties share the same secret point.

> ℹ️ Note: dot `·` means scalar multiplication and `×` integer multiplication.

---

### ❓ Why You Cannot Derive the Private Scalar from the Public Point

Given:

* `n`: the private scalar key
* `B`: the base point (public)
* `P = n · B`: the public key

Recovering `n` from `P` and `B` is equivalent to solving the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**.

This problem is considered **computationally infeasible** with current technology. No classical algorithm can efficiently recover `n` from `P` and `B`, even with massive computing power.

Only a large-scale **quantum computer** running Shor’s algorithm could break this — but such machines do not exist today.

---

### ⚠️ Avoid Using the Shared Secret Directly as a Shared Key

Many `(privateKey, publicKey)` pairs can produce the **same result `S`** when using `CryptoScalarMult`.
This is because `S` is a point on the curve, and scalar multiplication is not injective.

A safer and recommended approach is to derive a shared key using a cryptographic hash of the transcript:

```text
sharedKey = H(S || pk1 || pk2)
```

Or better use a key derivation function:

```text
sharedKey = KDF(S, pk1, pk2)
```

This binds the result to the specific public keys involved, preventing ambiguity or replay.
The order of the public keys must be agreed upon (e.g., lexicographically or based on fixed roles) to ensure both sides derive the same key.

---

### 📋 Recommended Derivation Pattern

This pattern illustrates how to compute a shared secret `S = n₁·P₂ = n₂·P₁`  and derive a symmetric key from it using `HKDF`.

The derivation uses:

- `ikm = S` (the shared secret point from scalar multiplication)
- `salt = senderPublicKey`
- `info = recipientPublicKey`

This ensures the derived key is uniquely bound to both the shared secret and the roles of the participants.

> 🤔 Tip: Swapping `salt` and `info` will produce a different key.  
> Be consistent across sender and recipient (e.g., always use sender's public key as salt).

This pattern prevents accidental key reuse and mitigates reflection or unknown key share attacks by incorporating both parties' public keys into the derivation process.



```csharp
using var alicePrivateKey = new SecureMemory<byte>(CryptoScalarMult.PrivateKeyLen);
Span<byte> alicePublicKey = stackalloc byte[CryptoScalarMult.PublicKeyLen];
RandomGenerator.Fill(alicePrivateKey);
CryptoScalarMult.CalculatePublicKey(alicePublicKey, alicePrivateKey);

using var bobPrivateKey = new SecureMemory<byte>(CryptoScalarMult.PrivateKeyLen);
Span<byte> bobPublicKey = stackalloc byte[CryptoScalarMult.PublicKeyLen];
RandomGenerator.Fill(bobPrivateKey);
CryptoScalarMult.CalculatePublicKey(bobPublicKey, bobPrivateKey);

using var aliceSharedSecret = new SecureMemory<byte>(CryptoScalarMult.PublicKeyLen);
CryptoScalarMult.Compute(aliceSharedSecret, alicePrivateKey, bobPublicKey);

using var bobSharedSecret = new SecureMemory<byte>(CryptoScalarMult.PublicKeyLen);
CryptoScalarMult.Compute(bobSharedSecret, bobPrivateKey, alicePublicKey);

bool isTheSameSharedSecret = aliceSharedSecret.AsReadOnlySpan()
    .SequenceEqual(bobSharedSecret.AsReadOnlySpan());

Debug.Assert(isTheSameSharedSecret, "Shared secrets should match between Alice and Bob.");

using var aliceTxKey = new SecureMemory<byte>(XChaCha20Poly1305.KeyLen);
CryptoHkdf.DeriveKey(HashAlgorithmName.SHA512, ikm: aliceSharedSecret, okm: aliceTxKey, 
	salt: alicePublicKey, info: bobPublicKey);

using var bobRxKey = new SecureMemory<byte>(XChaCha20Poly1305.KeyLen);
CryptoHkdf.DeriveKey(HashAlgorithmName.SHA512, ikm: bobSharedSecret, okm: bobRxKey, 
	salt: alicePublicKey, info: bobPublicKey);

bool isTheSameTxRxKey = aliceTxKey.AsReadOnlySpan().SequenceEqual(bobRxKey.AsReadOnlySpan());

Debug.Assert(isTheSameTxRxKey, "Transmission key derived by Alice should match receive key derived by Bob.");
```
---

## ⚠️ Error Handling

- `ArgumentException` — when input buffers have incorrect lengths or invalid parameters.
- `LibSodiumException` — when a crypto operation fails.

---

## 📝 Notes

* All APIs, except `SecureMemory` are Span-friendly and do not allocate memory internally.
* `CryptoScalarMult` is a low-level primitive and does not provide authentication.
* Avoid using scalar multiplication output directly as a key — always apply a key derivation function or a hash.

---

## 👀 See Also

* [CryptoKeyExchange](./KeyExchange.md)
* [CryptoBox](./CryptoBox.md)
* [CryptoHkdf](./Hashing.md)
* [API Reference: CryptoScalarMult](../api/LibSodium.CryptoScalarMult.yml)
* [libsodium scalar multiplication](https://doc.libsodium.org/advanced/scalar_multiplication)
* [RFC 7748 – X25519](https://datatracker.ietf.org/doc/html/rfc7748)

