# 🔑 Public Key Cryptography

LibSodium.Net provides high-level APIs for public-key cryptography based on Curve25519 and Ed25519. This includes secure encryption between peers (`CryptoBox`), anonymous encryption (`Sealed Boxes`), and digital signatures (`CryptoSign`). LibSodium.Net also exposes the low-level scalar multiplication primitive via `CryptoScalarMult`, which implements X25519.

> 🧂 Based on [libsodium's Public-Key Cryptography](https://doc.libsodium.org/public-key_cryptography/)<br/>
> 🧂 Based on [libsodium's Point*scalar multiplication](https://doc.libsodium.org/advanced/scalar_multiplication)<br/>
> ℹ️ [API Reference: CryptoBox](../api/LibSodium.CryptoBox.yml)<br/>
> ℹ️ [API Reference: CryptoSign](../api/LibSodium.CryptoSign.yml)
> ℹ️ [API Reference: CryptoScalarMult](../api/LibSodium.CryptoScalarMult.yml)

---

## 🌟 Features

* Public-key authenticated encryption (`CryptoBox`)
* Anonymous encryption for messages (Sealed Boxes)
* Digital signatures with Ed25519 (`CryptoSign`)
* Span-based APIs for efficient, allocation-free usage
* Conversion from Ed25519 keys to Curve25519 (`CryptoSign.PublicKeyToCurve`, `CryptoSign.PrivateKeyToCurve`)
* Keys and seeds can be provided as `SecureMemory<byte>`, `Span<byte>`/`ReadOnlySpan<byte>`, and `byte[]`.

---




---



---


---
## ⚠️ Error Handling

- `ArgumentException` — when input buffers have incorrect lengths or invalid parameters.
- `LibSodiumException` — when authentication fails or a crypto operation cannot complete.

## 📝 Notes

* Sealed boxes are anonymous: the recipient cannot identify the sender.
* `CryptoBox` uses `crypto_box_easy` internally; `CryptoSign` uses `crypto_sign_detached`.
* All APIs are Span-friendly and do not allocate memory internally.
* `EncryptWithPublicKey` prepends a 32-byte ephemeral public key and 16-byte MAC.
* Use `CryptoSign` when authentication is required **without** encryption.
* `CryptoScalarMult` is a low-level primitive and does not provide authentication.
* Avoid using scalar multiplication output directly as a key — always apply a hash.

---

## 👀 See Also

* [API Reference: CryptoBox](../api/LibSodium.CryptoBox.yml)
* [API Reference: CryptoSign](../api/LibSodium.CryptoSign.yml)
* [API Reference: CryptoScalarMult](../api/LibSodium.CryptoScalarMult.yml)
* [libsodium.org Public-Key Crypto](https://doc.libsodium.org/public-key_cryptography/)
* [libsodium scalar multiplication](https://doc.libsodium.org/advanced/scalar_multiplication)
* [RFC 7748 – X25519](https://datatracker.ietf.org/doc/html/rfc7748)

