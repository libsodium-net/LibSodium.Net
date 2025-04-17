# ✏️ Encoding

LibSodium.Net provides high-performance, secure encoding utilities to convert binary data to and from human-readable formats. The library currently supports two types of encoding:

- **Hexadecimal** via `HexEncoding`
- **Base64** via `Base64Encoding`

These classes are wrappers around libsodium's encoding utilities, providing constant-time and safe operations using spans.

> 🧂 Based on libsodium’s [Hexadecimal encoding/decoding](https://doc.libsodium.org/helpers#hexadecimal-encoding-decoding) and [Base64 encoding/decoding](https://doc.libsodium.org/helpers#base64-encoding-decoding)<br/>
> ℹ️ *See also:* [API Reference for `HexEncoding`](../api/LibSodium.HexEncoding.yml), [API Reference for `Base64Encoding`](../api/LibSodium.Base64Encoding.yml)

---

## 🔐 Security Considerations

These encoding functions are implemented in **constant time with respect to input size**, which means they avoid data-dependent branching and timing variations. This makes them **resistant to side-channel attacks**, such as timing attacks, which can leak information through observable differences in computation time.

LibSodium.Net ensures that these security properties are preserved in its managed API by:

- Using `Span<T>` and avoiding intermediate heap allocations.
- Delegating directly to libsodium’s hardened, constant-time implementations.

These properties make `HexEncoding` and `Base64Encoding` suitable for encoding sensitive data like cryptographic keys, hashes, tokens, and other secrets.

---

## ✨ HexEncoding

`HexEncoding` provides methods to encode a byte array into a lowercase hexadecimal string and decode from hexadecimal back into binary. All operations are span-based for performance and safety.

### 💻 Encode to hex

```csharp
Span<byte> bin = stackalloc byte[] { 0x01, 0x23, 0x45 };
string hex = HexEncoding.BinToHex(bin); // "012345"
```

You can also write the hex into a preallocated `Span<char>`:

```csharp
Span<char> hexBuffer = stackalloc char[bin.Length * 2];
HexEncoding.BinToHex(bin, hexBuffer);
```

### 💻 Decode from hex

```csharp
string hex = "0123456789abcdef";
Span<byte> buffer = stackalloc byte[hex.Length / 2];
HexEncoding.HexToBin(hex, buffer);
```

You can also ignore separators such as colons:

```csharp
string formatted = "01:23:45:67";
HexEncoding.HexToBin(formatted, buffer, ":");
```

### ⚠️ Exceptions
- `ArgumentException`: when hex buffer is too small.
- `LibSodiumException`: on malformed hex input or destination buffer too small.

---

##  ✨ Base64Encoding

`Base64Encoding` supports multiple Base64 variants, including URL-safe and no-padding modes.

### 📘 Base64 variants

```csharp
public enum Base64Variant
{
    Original,
    OriginalNoPadding,
    UrlSafe,
    UrlSafeNoPadding
}
```

These map directly to `sodium_base64_VARIANT_*` in libsodium.

### 💻 Encode to Base64

```csharp
Span<byte> bin = stackalloc byte[] { 1, 2, 3, 4 };
string b64 = Base64Encoding.BinToBase64(bin, Base64Variant.Original);
```

You can also write the result into a `Span<char>`:

```csharp
Span<char> buffer = stackalloc char[Base64Encoding.GetBase64EncodedLen(bin.Length, Base64Variant.Original)];
Base64Encoding.BinToBase64(bin, buffer, Base64Variant.Original);
```

### 💻 Decode from Base64

```csharp
string b64 = "AQIDBA==";
Span<byte> output = stackalloc byte[Base64Encoding.GetBase64DecodedMaxLen(b64.Length)];
Base64Encoding.Base64ToBin(b64, output, Base64Variant.Original);
```

Optional ignored characters (e.g., formatting spaces):

```csharp
Base64Encoding.Base64ToBin(" AQ ID BA == ", output, Base64Variant.Original, " ");
```

### ⚠️ Exceptions
- `ArgumentException`: buffer too small.
- `LibSodiumException`: invalid Base64 input or mismatched variant.

---

These encoding utilities are highly optimized, secure, and suitable for cryptographic applications where constant-time guarantees and low-level memory control are essential.

