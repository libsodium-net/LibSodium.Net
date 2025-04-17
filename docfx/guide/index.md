# 🔐 Introduction to LibSodium.Net

[**LibSodium.Net**](https://github.com/LibSodium-Net/LibSodium.Net) provides .NET developers with easy-to-use bindings for [libsodium](https://doc.libsodium.org/), a powerful, modern cryptography library widely recognized for its simplicity and security. This makes it straightforward to add robust cryptographic functionality to your .NET applications.

## ✨ Why LibSodium.Net?

- **Cross-platform**: Seamless support across Windows, Linux, and macOS.
- **Modern Cryptography**: Includes authenticated encryption, public-key cryptography, hashing, key derivation, and digital signatures.
- **Simple and Secure API**: Designed to reduce complexity, helping you implement cryptography correctly and securely.
- **Secure Memory Handling**: Sensitive data management to minimize risks like memory leaks or data exposure.
- **Span<T> over Arrays**: Optimized for performance and memory efficiency by using `Span<T>` instead of heap-allocated arrays.
- **AOT Compatible**: Uses `LibraryImport` (source-generated P/Invoke) instead of `DllImport`, making it fully compatible with AOT compilation environments.

---

# 🚀 Getting Started with LibSodium.Net

Here's how you can quickly integrate LibSodium.Net into your .NET projects.

## 📦 Install via NuGet

You can easily install LibSodium.Net using the NuGet package manager:

### CLI

```bash
dotnet add package LibSodium.Net
```

### Visual Studio

1. Right-click your project in Solution Explorer.
2. Choose **Manage NuGet Packages**.
3. Search for `LibSodium.Net` and click **Install**.

### Package Manager Console

```powershell
Install-Package LibSodium.Net
```

