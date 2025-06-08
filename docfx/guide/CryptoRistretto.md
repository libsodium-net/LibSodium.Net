# 🌀 CryptoRistretto — Operations on the Ristretto255 group

Ristretto255 provides a safer and simpler way to work with elliptic curves — specifically Curve25519 — by eliminating subtle issues and vulnerabilities that arise when using the curve directly.

It removes concerns like cofactors, low-order points, and invalid encodings, giving you a clean, prime-order group that's easier to reason about and safer to use in real-world protocols.

If you're building key exchanges, anonymous credentials, signatures, or zero-knowledge systems, Ristretto255 offers a robust foundation.

LibSodium.Net exposes the full Ristretto255 API from libsodium in a clear and idiomatic way.


---

## 📏 Constants

| Constant              | Value | Description                                  |
| --------------------- | ----- | -------------------------------------------- |
| `PointLen`            | 32    | Length of a Ristretto255 encoded point       |
| `ScalarLen`           | 32    | Length of a scalar                           |
| `HashLen`             | 64    | Input length for deriving points from a hash |
| `NonReducedScalarLen` | 64    | Input length for reduction to scalar mod L   |

---

## ✨ API Surface

| Method                 | Description                                                          |
| ---------------------- | -------------------------------------------------------------------- |
| `GenerateRandomScalar` | Fills a buffer with a random 32-byte scalar (modulo group order).    |
| `GenerateRandomPoint`  | Fills a buffer with a uniformly random valid Ristretto point.        |
| `ReduceScalar`         | Reduces a 64-byte value to a 32-byte scalar mod group order.         |
| `DerivePointFromHash`  | Maps a 64-byte hash to a valid Ristretto point.                      |
| `IsValidPoint`         | Returns true if the point is a valid Ristretto255 encoding.          |
| `NegateScalar`         | Computes the additive inverse of a scalar.                           |
| `ComplementScalar`     | Computes (L - 1 - s) mod L, where L is the group order.              |
| `InvertScalar`         | Computes the multiplicative inverse of a scalar mod group order.     |
| `AddScalars`           | Adds two scalars modulo group order.                                 |
| `SubtractScalars`      | Subtracts one scalar from another modulo group order.                |
| `MultiplyScalars`      | Multiplies two scalars (mod group order).                            |
| `AddPoints`            | Adds two Ristretto points.                                           |
| `SubtractPoints`       | Subtracts one Ristretto point from another.                          |
| `ScalarMultiply`       | Multiplies a point by a scalar.                                      |
| `ScalarMultiplyBase`   | Multiplies the base point by a scalar (used to compute public keys). |

---

## 📋 Examples

**Generate a random Ristretto255 point:**

```csharp
Span<byte> point = stackalloc byte[CryptoRistretto.PointLen];
CryptoRistretto.GenerateRandomPoint(point);
```

**Generate a random scalar and compute a public key:**

```csharp
using var sk = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
SecureMemory<byte> pk = SecureMemory.Create<byte>(CryptoRistretto.PointLen);
CryptoRistretto.GenerateRandomScalar(sk);
CryptoRistretto.ScalarMultiplyBase(sk, pk);
```

**Derive a point from a hash:**

```csharp
Span<byte> hash = stackalloc byte[CryptoRistretto.HashLen];
RandomNumberGenerator.Fill(hash);
Span<byte> point = stackalloc byte[CryptoRistretto.PointLen];
CryptoRistretto.DerivePointFromHash(hash, point);
```

**Multiply two scalars:**

```csharp
Span<byte> k1 = stackalloc byte[32];
Span<byte> k2 = stackalloc byte[32];
Span<byte> product = stackalloc byte[32];
RandomNumberGenerator.Fill(k1);
RandomNumberGenerator.Fill(k2);
CryptoRistretto.MultiplyScalars(k1, k2, product);
```

**Add two points:**

```csharp
Span<byte> p1 = stackalloc byte[32];
Span<byte> p2 = stackalloc byte[32];
Span<byte> sum = stackalloc byte[32];
CryptoRistretto.GenerateRandomPoint(p1);
CryptoRistretto.GenerateRandomPoint(p2);
CryptoRistretto.AddPoints(p1, p2, sum);
```

**Reduce a 64-byte value to a scalar:**

Useful for converting hashes, nonces, or user inputs into a valid scalar mod L.

```csharp
Span<byte> longValue = stackalloc byte[64];
Span<byte> reduced = stackalloc byte[32];
RandomNumberGenerator.Fill(longValue);
CryptoRistretto.ReduceScalar(longValue, reduced);
```

---

### 🔑 Authenticated Key Exchange and Encryption

This example shows how Alice and Bob can use Ristretto255 and HKDF to derive a shared secret `S = n₁·P₂ = n₂·P₁` from a Diffie-Hellman exchange.

The computed shared secret is then used to derive a symmetric key using `HKDF`. The derivation uses:

- `ikm = S` (the shared secret point from scalar multiplication)
- `salt = senderPublicKey`
- `info = recipientPublicKey`

This ensures the derived key is uniquely bound to both the shared secret and the roles of the participants.

The symmetric key is used to encrypt a message from Alice to Bob with `XChaCha20-Poly1305`.

> 🤔 Tip: Swapping `salt` and `info` will produce a different key.  
> Be consistent across sender and recipient (e.g., always use sender's public key as salt).

This pattern prevents accidental key reuse and mitigates reflection or unknown key share attacks by incorporating both parties' public keys into the derivation process. It also allows secure, authenticated, and forward-secret communication using ephemeral keys.

```csharp
using var aliceScalarSecret = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
using var bobScalarSecret = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
CryptoRistretto.GenerateRandomScalar(aliceScalarSecret);
CryptoRistretto.GenerateRandomScalar(bobScalarSecret);

Span<byte> alicePublicPoint = stackalloc byte[CryptoRistretto.PointLen];
Span<byte> bobPublicPoint = stackalloc byte[CryptoRistretto.PointLen];

CryptoRistretto.ScalarMultiplyBase(aliceScalarSecret, alicePublicPoint);
CryptoRistretto.ScalarMultiplyBase(bobScalarSecret, bobPublicPoint);

using var aliceSharedSecret = new SecureMemory<byte>(CryptoRistretto.PointLen);
using var bobSharedSecret = new SecureMemory<byte>(CryptoRistretto.PointLen);

CryptoRistretto.ScalarMultiply(bobScalarSecret, alicePublicPoint, bobSharedSecret);
CryptoRistretto.ScalarMultiply(aliceScalarSecret, bobPublicPoint, aliceSharedSecret);

bool isSameSharedSecret = aliceSharedSecret.AsReadOnlySpan()
	.SequenceEqual(bobSharedSecret.AsReadOnlySpan());

Debug.Assert(isSameSharedSecret, "The shared secrets should be equal.");

using var aliceTxKey = new SecureMemory<byte>(XChaCha20Poly1305.KeyLen);
CryptoHkdf.DeriveKey(HashAlgorithmName.SHA512, ikm: aliceSharedSecret, okm: aliceTxKey, salt: alicePublicPoint, info: bobPublicPoint);

var aliceMessageToBobPlaintext = "Hello Bob, this is Alice!"u8;

Span<byte> aliceMessageToBobCiphertext = stackalloc byte[aliceMessageToBobPlaintext.Length + XChaCha20Poly1305.MacLen + XChaCha20Poly1305.NonceLen];

XChaCha20Poly1305.Encrypt(aliceMessageToBobCiphertext, aliceMessageToBobPlaintext, aliceTxKey);

using var bobRxKey = new SecureMemory<byte>(XChaCha20Poly1305.KeyLen);
CryptoHkdf.DeriveKey(HashAlgorithmName.SHA512, ikm: bobSharedSecret, okm: bobRxKey, salt: alicePublicPoint, info: bobPublicPoint);

Span<byte> aliceMessageToBobDecrypted = stackalloc byte[aliceMessageToBobCiphertext.Length - XChaCha20Poly1305.MacLen - XChaCha20Poly1305.NonceLen];

XChaCha20Poly1305.Decrypt(aliceMessageToBobDecrypted, aliceMessageToBobCiphertext, bobRxKey);

bool isDecryptionValid = aliceMessageToBobDecrypted.SequenceEqual(aliceMessageToBobPlaintext);

Debug.Assert(isDecryptionValid, "Decrypted message should match original plaintext.");
```
---

### 🔢 Two-Party Computation (Oblivious Evaluation)

This example shows how two parties can evaluate a function of the form `f(x, k) = p(x)·k` — without revealing `x` to the evaluator, or `k` to the input holder.

Let:

* Party A holds a secret input `x`
* Party B holds a secret scalar `k`
* The goal is for A to obtain `p(x)·k`,
  where `p(x)` is a well-known hash-to-point function

#### Protocol steps:

1. A derives `p(x)` from `x`, generates a random scalar `r`, and blinds `p(x)`:

   ```
   a = p(x) + B·r
   ```

   where `B` is the base point of the group.

2. A sends `a` to B. B applies its secret scalar:

   ```
   b = a·k = (p(x) + B·r)·k = p(x)·k + B·(r·k)
   ```

3. B sends `b` to A. A removes the blinding term:

   * Computes `v = B·k` (received or derived from B)
   * Computes `v·(-r) = B·(-r·k)`
   * Adds it to `b`:

     ```
     fx = b + B·(-r·k) = p(x)·k
     ```

Thus, A obtains `p(x)·k` without learning `k`, and B never sees `x`.

---

> 🛡️ This technique is useful in privacy-preserving protocols like anonymous credentials, voting systems, or verifiable secret sharing.


```csharp

// Party A: has input x and computes p(x)
using var x = new SecureMemory<byte>(CryptoRistretto.HashLen);
RandomGenerator.Fill(x);

using var px = new SecureMemory<byte>(CryptoRistretto.PointLen);
// p(x) = hash-to-point(x)
CryptoRistretto.DerivePointFromHash(x, px); 

// A blinds p(x) using random scalar r
using var r = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
Span<byte> gr = stackalloc byte[CryptoRistretto.PointLen];
Span<byte> a = stackalloc byte[CryptoRistretto.PointLen];

CryptoRistretto.GenerateRandomScalar(r);
// g·r = base point scaled by r
CryptoRistretto.ScalarMultiplyBase(r, gr); 
// a = p(x) + g·r (blinded point sent to B)
CryptoRistretto.AddPoints(px.AsReadOnlySpan(), gr, a);      

// -------- Party B: evaluator --------
using var k = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
Span<byte> v = stackalloc byte[CryptoRistretto.PointLen];
Span<byte> b = stackalloc byte[CryptoRistretto.PointLen];

CryptoRistretto.GenerateRandomScalar(k);
// v = g·k (public key of B)
CryptoRistretto.ScalarMultiplyBase(k, v);    
// b = a·k = p(x)·k + g·(r·k)
CryptoRistretto.ScalarMultiply(k.AsReadOnlySpan(), a, b);        

// -------- Party A: unblinding --------
using var ir = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
Span<byte> vir = stackalloc byte[CryptoRistretto.PointLen];
using var fx = new SecureMemory<byte>(CryptoRistretto.PointLen);

// Compute -r
CryptoRistretto.NegateScalar(r, ir);
// Compute v·(-r) = g·(-r·k)
CryptoRistretto.ScalarMultiply(ir.AsReadOnlySpan(), v, vir); 
// Recover fx = b + g·(-r·k) = p(x)·k
CryptoRistretto.AddPoints(b, vir, fx.AsSpan());          

// Validate that fx == p(x)·k
using var expected = new SecureMemory<byte>(CryptoRistretto.PointLen);
CryptoRistretto.ScalarMultiply(k, px, expected);

bool isValid = fx.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan());
Debug.Assert(isValid, "The final result fx should match the expected value.");



```

> 💡 This protocol can serve as a building block for secure multiparty computation or threshold cryptography.

---

### 👀 See Also

* [libsodium Ristretto docs](https://doc.libsodium.org/advanced/point-arithmetic/ristretto)
* [CryptoScalarMult — X25519](CryptoScalarMult.md)
* [CryptoSign — Ed25519](CryptoSign.md)
* [CryptoHkdf — Key derivation](Hashing.md)
