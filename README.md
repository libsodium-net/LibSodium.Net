# LibSodium.Net

[![Build and Test](https://github.com/libSodium-net/LibSodium.Net/actions/workflows/build-and-test.yml/badge.svg)](https://github.com//libSodium-net/LibSodium.Net/actions/workflows/build-and-test.yml) [![NuGet](https://img.shields.io/nuget/v/LibSodium.Net.svg)](https://www.nuget.org/packages/LibSodium.Net/)


**LibSodium.Net** is a modern, idiomatic .NET binding for the [libsodium](https://doc.libsodium.org/) cryptographic library. It gives developers full access to libsodium’s capabilities through a minimal, transparent, and ergonomic C# API.

✨ **Secure by design. Fast by default. Unopinionated on purpose.**

## 🌟 Features

* Comprehensive API coverage of all major libsodium primitives
* Unified high-level API for all six AEAD algorithms
* Low-level bindings for granular control
* Ergonomic `Span<byte>`-based API with zero allocations where possible
* Optional automatic nonce generation and AAD support
* Deterministic key derivation helpers
* Detached and combined encryption modes
* AOT compatible

## 🧭 Design Philosophy

> *Expose all of libsodium’s capabilities exactly as they are, without hiding anything, while making them ergonomic for .NET developers.*

* **Transparent**: Everything maps 1:1 with libsodium, preserving guarantees and formats.
* **Ergonomic**: Natural to use with modern C# idioms (spans, overloads, optional params).
* **Minimal**: No opaque wrappers like `Key`, no hidden magic.
* **Unopinionated**: You structure your crypto; we give you the tools.

Built for developers who want control, clarity, and interop with other libsodium-based systems.

## 📚 Documentation

Full guide and API reference at [libsodium.net](https://libsodium.net/)

Includes:

* API-by-API documentation with examples
* Design notes and usage recommendations
* Code snippets with best practices

## 📦 Installation

Available on NuGet:

```bash
Install-Package LibSodium.Net -Version <latest>
```

## 🚀 Quick Start

```csharp
Span<byte> key = stackalloc byte[XChaCha20Poly1305.KeyLen];
RandomGenerator.Fill(key);

var plaintext = Encoding.UTF8.GetBytes("Hello world");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + XChaCha20Poly1305.MacLen + XChaCha20Poly1305.NonceLen];

XChaCha20Poly1305.Encrypt(ciphertext, plaintext, key);
```

## 🤝 Contributing

Issues and PRs are welcome. Please see the [contribution guide](CONTRIBUTING.md) if available.

## 📜 License

Apache-2.0. See [LICENSE](LICENSE).




