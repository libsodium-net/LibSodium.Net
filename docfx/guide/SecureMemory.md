# 🛡️ SecureMemory

When working with cryptographic data, it's essential to ensure that sensitive information doesn't get leaked through memory dumps or swapping. LibSodium.Net provides `SecureMemory` and `SecureMemory<T>` as robust tools to manage sensitive data safely in unmanaged memory.

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

> 🗝️ `SecureMemory<byte>` is used extensively across LibSodium.Net for handling **keys**, **seeds**, and other sensitive data. 
> It provides guarded unmanaged heap allocations with memory protection and automatic wiping, 
> making it the recommended type for storing cryptographic secrets.

---

## 📋 Basic Usage

```csharp
// Allocate secure memory. 
using var buffer = new SecureMemory<byte>(32); 

// Contents are initialized to 0x80 (for debugging purposes).
Debug.Assert(!buffer.IsZero());

// Optional: explicitly zero memory.
buffer.MemZero(); 

// Fill with random data.
RandomGenerator.Fill(buffer); 

// Write access 
var span = buffer.AsSpan(); 
var memory = buffer.AsMemory(); 

// Making it read-only prevents modifications.
buffer.ProtectReadOnly(); 

// access as read-only
var readOnlySpan = buffer.AsReadOnlySpan(); 
var readOnlyMemory = buffer.AsReadOnlyMemory(); 

// Make it writable again.
buffer.ProtectReadWrite(); 

```

---

## ✨ Safety Features

- Memory is initialized to 0x80 bytes.
- Accessing the `SecureMemory<T>` object after disposal throws `ObjectDisposedException`.
- Writing to memory after calling `ProtectReadOnly()` throws an `AccessViolationException`.
- `AsSpan()` and `AsMemory()` throw `InvalidOperationException` if the memory is protected with `ProtectReadOnly()`. Attempting to write using a previously obtained `Span<T>` or `Memory<T>` will trigger an `AccessViolationException`
- Memory is automatically zeroed out upon disposal using `sodium_memzero`.

---


## ⚠️ Security Considerations

- **Unmanaged memory isn't GC-tracked** — make sure to dispose properly.
- **AccessViolationException** is a sign that read/write protections are working as intended.
- **Avoid exposing memory** unnecessarily — always limit visibility.


