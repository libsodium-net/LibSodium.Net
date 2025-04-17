# 🛡️ SecureMemory

When working with cryptographic data, it's essential to ensure that sensitive information doesn't get leaked through memory dumps, swapping, or garbage collection. LibSodium.Net provides `SecureMemory` and `SecureMemory<T>` as robust tools to manage sensitive data safely in unmanaged memory.

>🧂 Backed by libsodium's [Secure memory](https://doc.libsodium.org/memory_management).<br/>
> ℹ️ *See also*: [API Reference for `SecureMemory<T>`](../api/LibSodium.SecureMemory-1.yml)

These APIs leverage libsodium’s `sodium_malloc`, `sodium_mlock`, and related memory protection functions to offer secure, optionally read-only memory regions that are wiped on disposal.

---

## ✨ SecureMemory&lt;T&gt;

`SecureMemory<T>` is a managed wrapper around unmanaged memory that stores a buffer of unmanaged type `T` items. It ensures:

- Memory is allocated using `sodium_allocarray`.
- Memory is wiped with `sodium_free` on disposal.
- Optional read-only protection using `ProtectReadOnly()`.
- Optional read-write toggle with `ProtectReadWrite()`.
- Safe access through `Span<T>`, `Memory<T>`, `ReadOnlySpan<T>`, and `ReadOnlyMemory<T>`.

---

## 💻 Basic Usage

```csharp
using var secure = SecureMemory.Create<byte>(32); // Allocate secure memory
var span = secure.AsSpan(); // Write access

RandomGenerator.Fill(span); // Fill with sensitive data

secure.ProtectReadOnly(); // Make it read-only
var readOnly = secure.AsReadOnlySpan(); // Safe read-only view
```

---

## ✨ Safety Features

- Accessing the `SecureMemory<T>` object after disposal throws `ObjectDisposedException`.
- Writing to memory after calling `ProtectReadOnly()` throws an `AccessViolationException`.
- Writing through a `Span<T>` previously obtained before calling `ProtectReadOnly()` also throws `AccessViolationException`.
- Memory is automatically zeroed out upon disposal using `sodium_memzero`.

---

## 📦 SecureMemory&lt;T&gt; Utilities

### 💻 Allocate Secure Buffers

```csharp
using var buffer = SecureMemory.Create<byte>(64);
```

### 💻 Zeroing Buffers

```csharp
buffer.MemZero(); // Overwrites memory with zeroes
```

### 💻 Protect Memory

```csharp
buffer.ProtectReadOnly();
buffer.ProtectReadWrite();
```

### 💻 Read-Only & Read-Write Access

- Use `.AsSpan()` to get mutable access.
- Use `.AsReadOnlySpan()` to get immutable view.

---

## ⚠️ Security Considerations

- **Unmanaged memory isn't GC-tracked** — make sure to dispose properly.
- **AccessViolationException** is a sign that read/write protections are working as intended.
- **Avoid exposing memory** unnecessarily — always limit visibility.


