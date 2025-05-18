# 🔐 SecretBox – Guide

# 🔒 Symmetric Authenticated Encryption with SecretBox

The `SecretBox` API in **LibSodium.Net** provides a simple and secure way to perform symmetric authenticated encryption using the XSalsa20 stream cipher and Poly1305 MAC. It supports both **combined** and **detached** encryption modes, as well as **manual** or **automatic** nonce handling — all from a single, unified API.

> 🧂Based on libsodium's [Authenticated encryption using `crypto_secretbox`](https://doc.libsodium.org/secret-key_cryptography/secretbox)<br/>
> ℹ️ *See also*: [API Reference for `SecretBox`](../api/LibSodium.SecretBox.yml)

---

## 🌟 Features

- Symmetric authenticated encryption using XSalsa20-Poly1305.
- Combined mode and detached mode support.
- Automatic or manual nonce handling.
- Built-in MAC verification (tamper detection).
- Unified `Encrypt` / `Decrypt` API with optional parameters.
- Safe and efficient `Span<T>`-based implementation.

---

## ✨ Encrypting and Decrypting Messages

Use the `Encrypt` and `Decrypt` methods. The behavior depends on whether you pass a `mac` buffer (detached) and/or a `nonce` (manual).

### 📋 Combined Mode (Auto Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
RandomGenerator.Fill(key);

var plaintext = Encoding.UTF8.GetBytes("Hello, auto-nonce world!");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + SecretBox.MacLen + SecretBox.NonceLen];

SecretBox.Encrypt(ciphertext, plaintext, key);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
SecretBox.Decrypt(decrypted, ciphertext, key);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

### 📋 Combined Mode (Manual Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
Span<byte> nonce = stackalloc byte[SecretBox.NonceLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(nonce);

var plaintext = Encoding.UTF8.GetBytes("Manual nonce combined");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + SecretBox.MacLen];

SecretBox.Encrypt(ciphertext, plaintext, key, nonce: nonce);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
SecretBox.Decrypt(decrypted, ciphertext, key, nonce: nonce);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

### 📋 Detached Mode (Auto Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
RandomGenerator.Fill(key);

var plaintext = Encoding.UTF8.GetBytes("Detached + auto nonce");
Span<byte> ciphertext = stackalloc byte[plaintext.Length + SecretBox.NonceLen];
Span<byte> mac = stackalloc byte[SecretBox.MacLen];

SecretBox.Encrypt(ciphertext, plaintext, key, mac);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
SecretBox.Decrypt(decrypted, ciphertext, key, mac);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

### 📋 Detached Mode (Manual Nonce)

```csharp
Span<byte> key = stackalloc byte[SecretBox.KeyLen];
Span<byte> nonce = stackalloc byte[SecretBox.NonceLen];
RandomGenerator.Fill(key);
RandomGenerator.Fill(nonce);

var plaintext = Encoding.UTF8.GetBytes("Detached with nonce");
Span<byte> ciphertext = stackalloc byte[plaintext.Length];
Span<byte> mac = stackalloc byte[SecretBox.MacLen];

SecretBox.Encrypt(ciphertext, plaintext, key, mac, nonce);

Span<byte> decrypted = stackalloc byte[plaintext.Length];
SecretBox.Decrypt(decrypted, ciphertext, key, mac, nonce);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

---

## ⚠️ Error Handling

- `ArgumentException` — invalid input sizes.
- `LibSodiumException` — authentication failed.

---

## 📝 Notes

- Nonce must be exactly `SecretBox.NonceLen` bytes when passed manually.
- Auto-nonce is prepended to the ciphertext when not specified.
- Combined mode outputs ciphertext + MAC (+ optional nonce).
- Detached mode separates MAC from ciphertext.
- Buffers can be larger than required.
- Always use `RandomGenerator.Fill()` for secure key and nonce generation.

---

## 👀 See Also

- [libsodium secretbox documentation](https://doc.libsodium.org/secret-key_cryptography/secretbox)
- [API Reference](../api/LibSodium.SecretBox.yml)

---

# 🧬 SecretBox.cs

```csharp
﻿using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides static methods for authenticated symmetric encryption and decryption using the Sodium secretbox primitives, 
	/// specifically the XSalsa20 stream cipher and Poly1305 MAC for authentication.
	/// These methods offer combined encryption/authentication and detached encryption/authentication, 
	/// with variations for handling nonces and Message Authentication Codes (MACs) within or separate from the ciphertext.
	/// </summary>
	public static partial class SecretBox
	{
		/// <summary>
		/// Represents the length of the encryption key in bytes.
		/// </summary>
		public const int KeyLen = Native.crypto_secretbox_KEYBYTES;
		/// <summary>
		/// Represents the length of the nonce (number used once) in bytes.
		/// </summary>
		public const int NonceLen = Native.crypto_secretbox_NONCEBYTES;
		/// <summary>
		/// represents the length of the Message Authentication Code (MAC) in bytes
		/// </summary>
		public const int MacLen = Native.crypto_secretbox_MACBYTES;

		/// <summary>
		/// Encrypts the provided plaintext using the specified key and nonce, writing the resulting ciphertext, 
		/// including the Message Authentication Code (MAC), to the provided ciphertext buffer.
		/// </summary>
		/// <param name="ciphertext">The buffer to receive the encrypted data, including the MAC. Must be at least <paramref name="plaintext"/> length plus <c>MacLen</c> bytes.</param>
		/// <param name="plaintext">The plaintext data to encrypt.</param>
		/// <param name="key">The encryption key. Must be <c>KeyLen</c> bytes in length.</param>
		/// <param name="nonce">The nonce (number used once) for encryption. Must be <c>NonceLen</c> bytes in length.</param>
		/// <returns>A span referencing the beginning of the <paramref name="ciphertext"/> buffer, containing the MAC followed by the encrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when:
		/// <list type="bullet">
		/// <item>The <paramref name="ciphertext"/> buffer is too small.</item>
		/// <item>The <paramref name="key"/> length is incorrect.</item>
		/// <item>The <paramref name="nonce"/> length is incorrect.</item>
		/// </list>
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown when the underlying encryption operation fails.</exception>
		internal static Span<byte> EncryptCombined(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
		{
			if (ciphertext.Length < plaintext.Length + MacLen)
			{
				throw new ArgumentException($"Ciphertext buffer must be at least as large as the plaintext buffer plus {MacLen} bytes.", nameof(ciphertext));
			}
			if (nonce.Length != NonceLen)
			{
				throw new ArgumentException($"Nonce must be {NonceLen} bytes in length.", nameof(nonce));
			}
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key must be {KeyLen} bytes in length.", nameof(key));
			}
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_secretbox_easy(ciphertext, plaintext, (ulong)plaintext.Length, nonce, key);
			if (rc != 0)
			{
				throw new LibSodiumException("Failed to encrypt message.");
			}
			return ciphertext.Slice(0, plaintext.Length + MacLen);
		}

		/// <summary>
		/// Encrypts the provided plaintext using the specified key and a randomly generated nonce, 
		/// writing the nonce, Message Authentication Code (MAC), and encrypted data to the provided ciphertext buffer.
		/// </summary>
		/// <param name="ciphertext">The buffer to receive the nonce, MAC, and encrypted data. Must be at least <paramref name="plaintext"/> length plus <c>MacLen</c> and <c>NonceLen</c> bytes.</param>
		/// <param name="plaintext">The plaintext data to encrypt.</param>
		/// <param name="key">The encryption key. Must be <c>KeyLen</c> bytes in length.</param>
		/// <returns>A span referencing the beginning of the <paramref name="ciphertext"/> buffer, containing the nonce, MAC, and then the encrypted data in that order.</returns>
		/// <exception cref="ArgumentException">Thrown when:
		/// <list type="bullet">
		/// <item>The <paramref name="ciphertext"/> buffer is too small.</item>
		/// <item>The <paramref name="key"/> length is incorrect.</item>
		/// </list>
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown when the underlying encryption operation fails.</exception>

		internal static Span<byte> EncryptCombined(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key)
		{
			if (ciphertext.Length < plaintext.Length + MacLen + NonceLen)
			{
				throw new ArgumentException($"Ciphertext buffer must be at least as large as the plaintext buffer plus {MacLen + NonceLen} bytes.", nameof(ciphertext));
			}
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key must be {KeyLen} bytes in length.", nameof(key));
			}
			Span<byte> nonce = ciphertext.Slice(0, NonceLen);
			LibraryInitializer.EnsureInitialized();
			RandomGenerator.Fill(nonce);
			var cipher = ciphertext.Slice(NonceLen);
			int rc = Native.crypto_secretbox_easy(cipher, plaintext, (ulong)plaintext.Length, nonce, key);
			if (rc != 0)
			{
				throw new LibSodiumException("Failed to encrypt message.");
			}
			return ciphertext.Slice(0, plaintext.Length + MacLen + NonceLen);
		}

		/// <summary>
		/// Decrypts the provided ciphertext, which has the Message Authentication Code (MAC) prepended, 
		/// using the specified key and nonce, writing the resulting plaintext to the provided buffer.
		/// </summary>
		/// <param name="plaintext">The buffer to receive the decrypted plaintext. Must be at least <paramref name="ciphertext"/> length minus <c>MacLen</c> bytes.</param>
		/// <param name="ciphertext">The ciphertext data to decrypt, which includes the MAC prepended. Must be at least <c>MacLen</c> bytes in length.</param>
		/// <param name="key">The decryption key. Must be <c>KeyLen</c> bytes in length.</param>
		/// <param name="nonce">The nonce (number used once) for decryption. Must be <c>NonceLen</c> bytes in length.</param>
		/// <returns>A span referencing the beginning of the <paramref name="plaintext"/> buffer, containing the decrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when:
		/// <list type="bullet">
		/// <item>The <paramref name="plaintext"/> buffer is too small.</item>
		/// <item>The <paramref name="ciphertext"/> buffer is too small.</item>
		/// <item>The <paramref name="key"/> length is incorrect.</item>
		/// <item>The <paramref name="nonce"/> length is incorrect.</item>
		/// </list>
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown when decryption or verification fails.</exception>

		internal static Span<byte> DecryptCombined(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
		{
			if (plaintext.Length < ciphertext.Length - MacLen)
			{
				throw new ArgumentException($"Plaintext buffer must be at least as large as the ciphertext buffer minus {MacLen} bytes.", nameof(plaintext));
			}
			if (ciphertext.Length < MacLen)
			{
				throw new ArgumentException($"Ciphertext buffer must be at least {MacLen} bytes in length.", nameof(ciphertext));
			}
			if (nonce.Length != NonceLen)
			{
				throw new ArgumentException($"Nonce must be {NonceLen} bytes in length.", nameof(nonce));
			}
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key must be {KeyLen} bytes in length.", nameof(key));
			}
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_secretbox_open_easy(plaintext, ciphertext, (ulong)ciphertext.Length, nonce, key);
			if (rc != 0)
			{
				throw new LibSodiumException("Couldn't decrypt message. Verification failed");
			}
			return plaintext.Slice(0, ciphertext.Length - MacLen);
		}

		/// <summary>
		/// Decrypts the provided ciphertext, which begins with the nonce and Message Authentication Code (MAC), 
		/// using the specified key, writing the resulting plaintext to the provided buffer.
		/// </summary>
		/// <param name="plaintext">The buffer to receive the decrypted plaintext. Must be at least <paramref name="ciphertext"/> length minus <c>MacLen</c> and <c>NonceLen</c> bytes.</param>
		/// <param name="ciphertext">The ciphertext data to decrypt, which begins with the nonce and MAC. Must be at least <c>MacLen</c> + <c>NonceLen</c> bytes in length.</param>
		/// <param name="key">The decryption key. Must be <c>KeyLen</c> bytes in length.</param>
		/// <returns>A span referencing the beginning of the <paramref name="plaintext"/> buffer, containing the decrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when:
		/// <list type="bullet">
		/// <item>The <paramref name="plaintext"/> buffer is too small.</item>
		/// <item>The <paramref name="ciphertext"/> buffer is too small.</item>
		/// <item>The <paramref name="key"/> length is incorrect.</item>
		/// </list>
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown when decryption or verification fails.</exception>

		internal static Span<byte> DecryptCombined(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key)
		{
			if (plaintext.Length < ciphertext.Length - MacLen - NonceLen)
			{
				throw new ArgumentException($"Plaintext buffer must be at least as large as the ciphertext buffer minus {MacLen} bytes.", nameof(plaintext));
			}
			if (ciphertext.Length < MacLen + NonceLen)
			{
				throw new ArgumentException($"Ciphertext buffer must be at least {MacLen + NonceLen} bytes in length.", nameof(ciphertext));
			}
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key must be {KeyLen} bytes in length.", nameof(key));
			}
			var nonce = ciphertext.Slice(0, NonceLen);
			var cipher = ciphertext.Slice(NonceLen);
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_secretbox_open_easy(plaintext, cipher, (ulong)cipher.Length, nonce, key);
			if (rc != 0)
			{
				throw new LibSodiumException("Couldn't decrypt message. Verification failed");
			}
			return plaintext.Slice(0, ciphertext.Length - MacLen - NonceLen);
		}

		/// <summary>
		/// Encrypts the provided plaintext using the specified key and nonce, producing a detached Message Authentication Code (MAC) and writing the encrypted plaintext to the ciphertext buffer.
		/// </summary>
		/// <param name="ciphertext">The buffer to receive the encrypted plaintext. Must be at least the same size as <paramref name="plaintext"/>.</param>
		/// <param name="mac">The buffer to receive the generated Message Authentication Code (MAC). Must be <c>MacLen</c> bytes in length.</param>
		/// <param name="plaintext">The plaintext data to encrypt.</param>
		/// <param name="key">The encryption key. Must be <c>KeyLen</c> bytes in length.</param>
		/// <param name="nonce">The nonce (number used once) for encryption. Must be <c>NonceLen</c> bytes in length.</param>
		/// <returns>A span referencing the beginning of the <paramref name="ciphertext"/> buffer, containing the encrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when:
		/// <list type="bullet">
		/// <item>The <paramref name="ciphertext"/> buffer is too small.</item>
		/// <item>The <paramref name="mac"/> buffer is the incorrect length.</item>
		/// <item>The <paramref name="nonce"/> length is incorrect.</item>
		/// <item>The <paramref name="key"/> length is incorrect.</item>
		/// </list>
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown when the encryption operation fails.</exception>
		internal static Span<byte> EncryptDetached(Span<byte> ciphertext, Span<byte> mac, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
		{
			if (ciphertext.Length < plaintext.Length)
			{
				throw new ArgumentException("Ciphertext buffer must be at least as large as the plaintext buffer.", nameof(ciphertext));
			}
			if (mac.Length != MacLen)
			{
				throw new ArgumentException($"MAC buffer must be {MacLen} bytes in length.", nameof(mac));
			}
			if (nonce.Length != NonceLen)
			{
				throw new ArgumentException($"Nonce must be {NonceLen} bytes in length.", nameof(nonce));
			}
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key must be {KeyLen} bytes in length.", nameof(key));
			}
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_secretbox_detached(ciphertext, mac, plaintext, (ulong)plaintext.Length, nonce, key);
			if (rc != 0)
			{
				throw new LibSodiumException("Failed to encrypt message.");
			}
			return ciphertext.Slice(0, plaintext.Length);
		}

		/// <summary>
		/// Encrypts the provided plaintext using the specified key and a randomly generated nonce, producing a detached Message Authentication Code (MAC) 
		/// and writing the nonce followed by the encrypted plaintext to the ciphertext buffer.
		/// </summary>
		/// <param name="ciphertext">The buffer to receive the randomly generated nonce followed by the encrypted plaintext. Must be at least <paramref name="plaintext"/> length plus <c>NonceLen</c> bytes.</param>
		/// <param name="mac">The buffer to receive the generated Message Authentication Code (MAC). Must be <c>MacLen</c> bytes in length.</param>
		/// <param name="plaintext">The plaintext data to encrypt.</param>
		/// <param name="key">The encryption key. Must be <c>KeyLen</c> bytes in length.</param>
		/// <returns>A span referencing the beginning of the <paramref name="ciphertext"/> buffer, containing the nonce followed by the encrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when:
		/// <list type="bullet">
		/// <item>The <paramref name="ciphertext"/> buffer is too small.</item>
		/// <item>The <paramref name="mac"/> buffer has an incorrect length.</item>
		/// <item>The <paramref name="key"/> buffer has an incorrect length.</item>
		/// </list>
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown when the encryption operation fails.</exception>
		internal static Span<byte> EncryptDetached(Span<byte> ciphertext, Span<byte> mac, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key)
		{
			if (ciphertext.Length < plaintext.Length + NonceLen)
			{
				throw new ArgumentException($"Ciphertext buffer must be at least as large as the plaintext buffer plus {NonceLen} bytes.", nameof(ciphertext));
			}
			if (mac.Length != MacLen)
			{
				throw new ArgumentException($"MAC buffer must be {MacLen} bytes in length.", nameof(mac));
			}
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key must be {KeyLen} bytes in length.", nameof(key));
			}
			Span<byte> nonce = ciphertext.Slice(0, NonceLen);
			LibraryInitializer.EnsureInitialized();
			RandomGenerator.Fill(nonce);
			var cipher = ciphertext.Slice(NonceLen);
			int rc = Native.crypto_secretbox_detached(cipher, mac, plaintext, (ulong)plaintext.Length, nonce, key);
			if (rc != 0)
			{
				throw new LibSodiumException("Failed to encrypt message.");
			}
			return ciphertext.Slice(0, plaintext.Length + NonceLen);
		}

		/// <summary>
		/// Decrypts the provided ciphertext using the specified key, nonce, and Message Authentication Code (MAC), writing the resulting plaintext to the provided buffer.
		/// </summary>
		/// <param name="plaintext">The buffer to receive the decrypted plaintext. Must be at least the same size as <paramref name="ciphertext"/>.</param>
		/// <param name="ciphertext">The ciphertext data to decrypt.</param>
		/// <param name="key">The decryption key. Must be <c>KeyLen</c> bytes in length.</param>
		/// <param name="mac">The Message Authentication Code (MAC) for verification. Must be <c>MacLen</c> bytes in length.</param>
		/// <param name="nonce">The nonce (number used once) for decryption. Must be <c>NonceLen</c> bytes in length.</param>
		/// <returns>A span referencing the beginning of the <paramref name="plaintext"/> buffer, containing the decrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when:
		/// <list type="bullet">
		/// <item>The <paramref name="plaintext"/> buffer is too small.</item>
		/// <item>The <paramref name="mac"/>  length is incorrect.</item>
		/// <item>The <paramref name="nonce"/> length is incorrect.</item>
		/// <item>The <paramref name="key"/> length is incorrect.</item>
		/// </list>
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown when decryption or verification fails.</exception>
		internal static Span<byte> DecryptDetached(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> nonce)
		{
			if (plaintext.Length < ciphertext.Length)
			{
				throw new ArgumentException("Plaintext buffer must be at least as large as the ciphertext buffer.", nameof(plaintext));
			}
			if (mac.Length != MacLen)
			{
				throw new ArgumentException($"MAC buffer must be {MacLen} bytes in length.", nameof(mac));
			}
			if (nonce.Length != NonceLen)
			{
				throw new ArgumentException($"Nonce must be {NonceLen} bytes in length.", nameof(nonce));
			}
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key must be {KeyLen} bytes in length.", nameof(key));
			}
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_secretbox_open_detached(plaintext, ciphertext, mac, (ulong)ciphertext.Length, nonce, key);
			if (rc != 0)
			{
				throw new LibSodiumException("Couldn't decrypt message. Verification failed");
			}
			return plaintext.Slice(0, ciphertext.Length);
		}

		/// <summary>
		/// Decrypts the provided ciphertext, which starts with the nonce, using the specified key and Message Authentication Code (MAC), 
		/// writing the resulting plaintext to the provided buffer.
		/// </summary>
		/// <param name="plaintext">The buffer to receive the decrypted plaintext. Must be at least <paramref name="ciphertext"/> length minus <c>NonceLen</c> bytes.</param>
		/// <param name="ciphertext">The ciphertext data to decrypt, which starts with the nonce. Must be at least <c>NonceLen</c> bytes in length.</param>
		/// <param name="key">The decryption key. Must be <c>KeyLen</c> bytes in length.</param>
		/// <param name="mac">The Message Authentication Code (MAC) for verification. Must be <c>MacLen</c> bytes in length.</param>
		/// <returns>A span referencing the beginning of the <paramref name="plaintext"/> buffer, containing the decrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when:
		/// <list type="bullet">
		/// <item>The <paramref name="plaintext"/> buffer is too small.</item>
		/// <item>The <paramref name="mac"/> length is incorrect.</item>
		/// <item>The <paramref name="key"/> length is incorrect.</item>
		/// <item>The <paramref name="ciphertext"/> length is too small.</item>
		/// </list>
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown when decryption or verification fails.</exception>

		internal static Span<byte> DecryptDetached(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> mac)
		{
			if (plaintext.Length < ciphertext.Length - NonceLen)
			{
				throw new ArgumentException("Plaintext buffer must be at least as large as the ciphertext buffer.", nameof(plaintext));
			}
			if (mac.Length != MacLen)
			{
				throw new ArgumentException($"MAC buffer must be {MacLen} bytes in length.", nameof(mac));
			}
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key must be {KeyLen} bytes in length.", nameof(key));
			}
			var nonce = ciphertext.Slice(0, NonceLen);
			var cipher = ciphertext.Slice(NonceLen);
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_secretbox_open_detached(plaintext, cipher, mac, (ulong)cipher.Length, nonce, key);
			if (rc != 0)
			{
				throw new LibSodiumException("Couldn't decrypt message. Verification failed");
			}
			return plaintext.Slice(0, ciphertext.Length - NonceLen);
		}

		/// <summary>
		/// Encrypts a message using XSalsa20-Poly1305. Supports combined and detached modes, with optional manual nonce.
		/// </summary>
		/// <param name="ciphertext">
		/// The output buffer. In combined mode, it must include space for the MAC and, if auto-nonce is used, also for the nonce.
		/// In detached mode with auto-nonce, the nonce is prepended.
		/// It can be longer than needed.
		/// </param>
		/// <param name="plaintext">The plaintext to encrypt.</param>
		/// <param name="key">The secret key (32 bytes).</param>
		/// <param name="mac">
		/// Optional. If provided, encryption is done in detached mode and the MAC is written to this buffer.
		/// Otherwise, combined mode is used.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided, a random nonce is generated and prepended to the ciphertext.
		/// </param>
		/// <returns>The span representing the encrypted ciphertext, which may include MAC and nonce depending on the mode.</returns>
		public static Span<byte> Encrypt(
			Span<byte> ciphertext,
			ReadOnlySpan<byte> plaintext,
			ReadOnlySpan<byte> key,
			Span<byte> mac = default,
			ReadOnlySpan<byte> nonce = default)
		{
			if (mac == default)
			{
				// Combined mode
				if (nonce == default)
					return EncryptCombined(ciphertext, plaintext, key);
				else
					return EncryptCombined(ciphertext, plaintext, key, nonce);
			}
			else
			{
				// Detached mode
				if (nonce == default)
					return EncryptDetached(ciphertext, mac, plaintext, key);
				else
					return EncryptDetached(ciphertext, mac, plaintext, key, nonce);
			}
		}

		/// <summary>
		/// Decrypts a message using XSalsa20-Poly1305. Supports combined and detached modes, with optional manual nonce.
		/// </summary>
		/// <param name="plaintext">
		/// The buffer to receive the decrypted message.
		/// Must be at least ciphertext length minus MAC and/or nonce depending on mode.
		/// It can be longer than needed.
		/// </param>
		/// <param name="ciphertext">
		/// The encrypted message. May include MAC and/or nonce depending on the mode.
		/// </param>
		/// <param name="key">The secret key (32 bytes).</param>
		/// <param name="mac">
		/// Optional. If provided, decryption is done in detached mode using this MAC.
		/// Otherwise, combined mode is used.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided, it is extracted from the ciphertext (auto-nonce mode).
		/// </param>
		/// <returns>The span representing the recovered plaintext.</returns>
		public static Span<byte> Decrypt(
			Span<byte> plaintext,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> key,
			ReadOnlySpan<byte> mac = default,
			ReadOnlySpan<byte> nonce = default)
		{
			if (mac == default)
			{
				// Combined mode
				if (nonce == default)
					return DecryptCombined(plaintext, ciphertext, key);
				else
					return DecryptCombined(plaintext, ciphertext, key, nonce);
			}
			else
			{
				// Detached mode
				if (nonce == default)
					return DecryptDetached(plaintext, ciphertext, key, mac);
				else
					return DecryptDetached(plaintext, ciphertext, key, mac, nonce);
			}
		}
	}
}

```

# 🧪 SecretBoxTests.cs

```csharp
﻿using TUnit.Assertions.AssertConditions.Throws;

using static LibSodium.SecretBox;

namespace LibSodium.Tests
{
	public class SecretBoxTests
	{
		private static byte[] GenerateRandomPlainText()
		{
			var plaintextLen = 32 + RandomGenerator.GetUInt32(upperBound: 16);
			var plaintext = new byte[plaintextLen];
			RandomGenerator.Fill(plaintext);
			return plaintext;
		}

		[Test]
		public void EncryptCombined_DecryptCombined_Success()
		{
			Span<byte> key = stackalloc byte[SecretBox.KeyLen];
			Span<byte> nonce = stackalloc byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			Span<byte> ciphertextBuffer = stackalloc byte[plaintext.Length + SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce);
			var ciphertextLen = ciphertext.Length;
			Span<byte> decryptedBuffer = stackalloc byte[plaintext.Length];
			var decrypted = SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key, nonce).ToArray();

			ciphertextLen.ShouldBe(plaintext.Length + SecretBox.MacLen);
			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptCombined_AutoNonce_DecryptCombined_AutoNonce_Success()
		{
			Span<byte> key = stackalloc byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			Span<byte> ciphertextBuffer = stackalloc byte[plaintext.Length + SecretBox.MacLen + SecretBox.NonceLen];

			var ciphertext = SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key);
			Span<byte> decryptedBuffer = stackalloc byte[plaintext.Length];
			var decrypted = SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key).ToArray();
			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptDetached_DecryptDetached_Success()
		{
			Span<byte> key = stackalloc byte[SecretBox.KeyLen];
			Span<byte> nonce = stackalloc byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			Span<byte> ciphertextBuffer = stackalloc byte[plaintext.Length];
			Span<byte> macBuffer = stackalloc byte[SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptDetached(ciphertextBuffer, macBuffer, plaintext, key, nonce);
			Span<byte> decryptedBuffer = stackalloc byte[plaintext.Length];
			var decrypted = SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer, nonce).ToArray();
			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptDetached_AutoNonce_DecryptDetached_AutoNonce_Success()
		{
			Span<byte> key = stackalloc byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			Span<byte> ciphertextBuffer = stackalloc byte[plaintext.Length + SecretBox.NonceLen];
			Span<byte> macBuffer = stackalloc byte[SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptDetached(ciphertextBuffer, macBuffer, plaintext, key);
			Span<byte> decryptedBuffer = stackalloc byte[plaintext.Length];
			var decrypted = SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer).ToArray();

			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void EncryptCombined_InvalidCiphertextBuffer_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen - 1]; // Buffer too small

			AssertLite.Throws<ArgumentException>(() =>
			{
				SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce);
			});

		}

		[Test]
		public void EncryptCombined_InvalidKeyLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen - 1];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen];

			AssertLite.Throws<ArgumentException>(() =>
			{
				SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce);
			});
		}

		[Test]
		public void EncryptCombined_InvalidNonceLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen - 1];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen];

			AssertLite.Throws<ArgumentException>(() =>
			{
				SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce);
			});
		}

		[Test]
		public void DecryptCombined_InvalidCiphertextLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			byte[] ciphertextBuffer = new byte[SecretBox.MacLen - 1]; // Buffer too small
			byte[] plaintextBuffer = new byte[10];

			AssertLite.Throws<ArgumentException>(() =>
			{
				SecretBox.DecryptCombined(plaintextBuffer, ciphertextBuffer, key, nonce);
			});
		}

		[Test]
		public void DecryptDetached_InvalidMacLength_ThrowsArgumentException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			byte[] ciphertextBuffer = new byte[10];
			byte[] macBuffer = new byte[SecretBox.MacLen - 1]; // mac too short
			byte[] plaintextBuffer = new byte[10];

			AssertLite.Throws<ArgumentException>(() =>
			{
				SecretBox.DecryptDetached(plaintextBuffer, ciphertextBuffer, key, macBuffer, nonce);
			});
		}

		[Test]
		public void DecryptCombined_TamperedCiphertext_ThrowsSodiumException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key, nonce).ToArray(); // Convert to Array to be safe.

			// Tamper with the ciphertext by flipping a bit
			ciphertext[5] ^= 0b00000001; // Flip the 1st bit of the 6th byte

			byte[] decryptedBuffer = new byte[plaintext.Length];

			AssertLite.Throws<LibSodiumException>(() =>
			{
				SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key, nonce);
			});
		}

		[Test]
		public void DecryptCombined_AutoNonce_TamperedCiphertext_ThrowsSodiumException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.MacLen + SecretBox.NonceLen];

			var ciphertext = SecretBox.EncryptCombined(ciphertextBuffer, plaintext, key).ToArray(); // Convert to Array to be safe.

			// Tamper with the ciphertext by changing a byte
			ciphertext[SecretBox.NonceLen + 10] ^= 0xFF; // Change the 11th byte after nonce

			byte[] decryptedBuffer = new byte[plaintext.Length];

			AssertLite.Throws<LibSodiumException>(() =>
			{
				SecretBox.DecryptCombined(decryptedBuffer, ciphertext, key);
			});
		}

		[Test]
		public void DecryptDetached_TamperedCiphertext_ThrowsSodiumException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			byte[] nonce = new byte[SecretBox.NonceLen];
			RandomGenerator.Fill(key);
			RandomGenerator.Fill(nonce);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length];
			byte[] macBuffer = new byte[SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptDetached(ciphertextBuffer, macBuffer, plaintext, key, nonce).ToArray(); // Convert to array.

			// Tamper with the ciphertext by flipping a bit
			ciphertext[15] ^= 0b00000001; // Flip the 1st bit of the 16th byte

			byte[] decryptedBuffer = new byte[plaintext.Length];

			AssertLite.Throws<LibSodiumException>(() =>
			{
				SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer, nonce);
			});
		}

		[Test]
		public void DecryptDetached_AutoNonce_TamperedCiphertext_ThrowsSodiumException()
		{
			byte[] key = new byte[SecretBox.KeyLen];
			RandomGenerator.Fill(key);

			var plaintext = GenerateRandomPlainText();
			byte[] ciphertextBuffer = new byte[plaintext.Length + SecretBox.NonceLen];
			byte[] macBuffer = new byte[SecretBox.MacLen];

			var ciphertext = SecretBox.EncryptDetached(ciphertextBuffer, macBuffer, plaintext, key).ToArray(); // Convert to array.

			// Tamper with the ciphertext by changing a byte
			ciphertext[SecretBox.NonceLen + 20] ^= 0xFF; // Change the 21th byte after nonce

			byte[] decryptedBuffer = new byte[plaintext.Length];

			AssertLite.Throws<LibSodiumException>(() =>
			{
				SecretBox.DecryptDetached(decryptedBuffer, ciphertext, key, macBuffer);
			});
		}

		private static byte[] GenerateRandomBytes(int length)
		{
			var buffer = new byte[length];
			Random.Shared.NextBytes(buffer);
			return buffer;
		}

		[Test]
		public void AllCombinedOptions()
		{
			var key = GenerateRandomBytes(KeyLen);
			var nonce = GenerateRandomBytes(NonceLen);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[NonceLen + plaintext.Length + MacLen];
			var decrypted = new byte[plaintext.Length];

			Span<byte> encrypted;

			encrypted = Encrypt(ciphertext, plaintext, key);
			Decrypt(decrypted, encrypted, key);
			decrypted.ShouldBe(plaintext);

			encrypted = Encrypt(ciphertext, plaintext, key, nonce: nonce);
			Decrypt(decrypted, encrypted, key, nonce: nonce);
			decrypted.ShouldBe(plaintext);
		}

		[Test]
		public void AllDetachedOptions()
		{
			var key = GenerateRandomBytes(KeyLen);
			var nonce = GenerateRandomBytes(NonceLen);
			var plaintext = GenerateRandomBytes(64);
			var ciphertext = new byte[NonceLen + plaintext.Length];
			var decrypted = new byte[plaintext.Length];
			var mac = new byte[MacLen];

			Span<byte> encrypted;

			encrypted = Encrypt(ciphertext, plaintext, key, mac: mac);
			Decrypt(decrypted, encrypted, key, mac: mac);
			decrypted.ShouldBe(plaintext);

			encrypted = Encrypt(ciphertext, plaintext, key, mac: mac, nonce: nonce);
			Decrypt(decrypted, encrypted, key, mac: mac, nonce: nonce);
			decrypted.ShouldBe(plaintext);
		}
	}
}
```

# 🔐 SecretStream – Guide

# 🔒 Authenticated Stream Encryption with SecretStream

The `SecretStream` class in **LibSodium.Net** provides secure, authenticated stream-based encryption and decryption using the **XChaCha20-Poly1305** algorithm. It's designed to handle large streams of data efficiently and securely.

>🧂 Based on libsodium's [Encrypted streams and file encryption](https://doc.libsodium.org/secret-key_cryptography/secretstream)<br/>
> ℹ️ *See also*: [API Reference for `SecretStream`](../api/LibSodium.SecretStream.yml)

---

## ✨ Key Features

- Authenticated encryption ensures data integrity.
- Automatic chunking and handling of large data streams.
- Secure random key generation.
- Protection against nonce reuse.

---

## ✨ Basic Usage

### 📋 Generating a Secret Key

A secret key must be securely generated and managed:

```csharp
byte[] key = new byte[CryptoSecretStream.KeyLen];
CryptoSecretStream.GenerateKey(key);
```

### 📋 Encrypting Data

Encrypting data streams asynchronously:

```csharp
using var inputFile = File.OpenRead("plaintext.dat");
using var encryptedFile = File.Create("encrypted.dat");

await SecretStream.EncryptAsync(inputFile, encryptedFile, key);
```

Synchronous Encryption:

```csharp
using var inputFile = File.OpenRead("plaintext.dat");
using var encryptedFile = File.Create("encrypted.dat");

SecretStream.Encrypt(inputFile, encryptedFile, key);
```

### 📋 Decrypting Data

Decrypting asynchronously the encrypted data back to plaintext:

```csharp
using var encryptedFile = File.OpenRead("encrypted.dat");
using var decryptedFile = File.Create("decrypted.dat");

await SecretStream.DecryptAsync(encryptedFile, decryptedFile, key);
```

Synchronous Decryption:

```csharp
using var encryptedFile = File.OpenRead("encrypted.dat");
using var decryptedFile = File.Create("decrypted.dat");

SecretStream.Decrypt(encryptedFile, decryptedFile, key);
```

---

## ⚠️ Security Considerations

- **Secure Key Management:** Protect your keys; losing them or exposing them compromises security.
- **Nonce Management:** Handled internally by `SecretStream`; avoid manual nonce reuse.
- **Integrity Checks:** Automatic using Poly1305 tags; any tampering results in exceptions.

---

## ⚠️ Error Handling

Encryption and decryption throw specific exceptions for error conditions:

- `ArgumentException`: Invalid arguments (wrong key length, null streams).
- `LibSodiumException`: Authentication failed, typically from tampered data.

---

## 🕒 Performance Considerations

- `SecretStream` processes data in chunks (default: 64KB) for optimal balance between memory usage and performance.
- Utilize asynchronous methods (`EncryptAsync`/`DecryptAsync`) for IO-bound scenarios for better scalability.


---

# 🧬 SecretStream.cs

```csharp
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member


using System.Buffers;
using System.Security.Cryptography;

namespace LibSodium;

/// <summary>
/// Provides high-level, stream-based authenticated encryption and decryption
/// using the XChaCha20-Poly1305 algorithm. This class abstracts the complexity
/// of securely processing large data streams, including chunking, authentication,
/// and cryptographic state management.
/// </summary>
/// <remarks>
/// <para>
/// This class is built on LibSodium’s <c>crypto_secretstream_xchacha20poly1305</c> API,
/// using XChaCha20 for encryption and Poly1305 for message authentication. The large
/// 192-bit nonce (24 bytes) virtually eliminates the risk of nonce reuse when generated randomly.
/// </para>
/// <para>
/// The stream is processed in fixed-size chunks (64 KB), each individually encrypted
/// and authenticated. A randomly generated header (nonce and metadata) is prepended
/// to the stream and required for successful decryption.
/// </para>
/// <para>
/// <b>Security Considerations:</b>
/// <list type="bullet">
/// <item><b>Key Management:</b> Keys must be generated securely and stored safely.
/// Compromise of the key invalidates confidentiality and integrity guarantees.</item>
/// <item><b>Nonce Handling:</b> Nonces are generated internally. Do not reuse headers
/// or keys manually unless you know what you're doing.</item>
/// <item><b>Integrity:</b> Poly1305 tags ensure tampering is detected during decryption.
/// Any modification will result in decryption failure.</item>
/// </list>
/// </para>
/// </remarks>
public static class SecretStream

{
	/// <summary>
	/// The size of each plaintext chunk processed during encryption (64KB).
	/// This chunk size is used to divide the input stream into manageable blocks.
	/// </summary>
	public const int PlainChunkSize = 64 * 1024; // 64KB

	/// <summary>
	/// The size of each ciphertext chunk written to the output stream. This includes
	/// the size of the corresponding plaintext chunk plus the overhead added by the
	/// encryption and authentication process (typically 17 bytes for XChaCha20-Poly1305).
	/// </summary>
	private static readonly int CipherChunkSize = PlainChunkSize + CryptoSecretStream.OverheadLen;


	/// <summary>
	/// Asynchronously encrypts data from the <paramref name="input"/> stream and writes the ciphertext
	/// to the <paramref name="output"/> stream using the XChaCha20-Poly1305 algorithm.
	/// </summary>
	/// <param name="input">The readable stream containing plaintext to encrypt.</param>
	/// <param name="output">The writable stream where ciphertext will be written.</param>
	/// <param name="key">
	/// The secret key for encryption. Must be securely generated and kept confidential.
	/// Typically 32 bytes in length for XChaCha20-Poly1305.
	/// </param>
	/// <param name="cancellationToken">Optional token to cancel the asynchronous operation.</param>
	/// <returns>A task representing the asynchronous encryption process.</returns>
	/// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
	/// <exception cref="OperationCanceledException">Thrown if the operation is canceled.</exception>
	/// <remarks>
	/// <para>
	/// The input stream is read in <see cref="PlainChunkSize"/> blocks. Each block is encrypted
	/// and written to the output stream with an authentication tag to ensure integrity.
	/// </para>
	/// <para>
	/// A cryptographic header (including a randomly generated nonce) is prepended to the output.
	/// This header is required for successful decryption.
	/// </para>
	/// <para>
	/// The encryption state is maintained internally and finalized when the last chunk is written
	/// with the <see cref="CryptoSecretStreamTag.Final"/> tag.
	/// </para>
	/// <para>
	/// <b>Note:</b> The caller is responsible for managing the lifetime of the input/output streams.
	/// They are not closed or disposed automatically.
	/// </para>
	/// </remarks>
	public static async Task EncryptAsync(
		Stream input,
		Stream output,
		ReadOnlyMemory<byte> key,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(input, nameof(input));
		ArgumentNullException.ThrowIfNull(output, nameof(output));
		ArgumentNullException.ThrowIfNull(key, nameof(key));
		byte[]? cipherBuffer = null;
		byte[]? plainBuffer = null;
		try
		{
			cipherBuffer = ArrayPool<byte>.Shared.Rent(CipherChunkSize);
			plainBuffer = ArrayPool<byte>.Shared.Rent(PlainChunkSize);
		}
		catch
		{
			TryReturnBuffers(cipherBuffer, plainBuffer);
			throw;
		}
		byte[] stateBuffer = new byte[CryptoSecretStream.StateLen];
		byte[] headerBuffer = new byte[CryptoSecretStream.HeaderLen];

		try
		{
			CryptoSecretStream.InitializeEncryption(stateBuffer, headerBuffer, key.Span);
			await output.WriteAsync(headerBuffer, cancellationToken).ConfigureAwait(false);

			int bufferFill = 0;
			bool endOfStream = false;

			while (!endOfStream)
			{
				bufferFill = await FillBufferAsync(input, plainBuffer, 0, PlainChunkSize, cancellationToken).ConfigureAwait(false);
				endOfStream = bufferFill < PlainChunkSize;

				var tag = endOfStream ? CryptoSecretStreamTag.Final : CryptoSecretStreamTag.Message;

				var written = CryptoSecretStream.EncryptChunk(
					stateBuffer,
					cipherBuffer,
					plainBuffer.AsSpan(0, bufferFill),
					tag
				).Length;

				await output.WriteAsync(cipherBuffer.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
			}
		}
		finally
		{
			SecureMemory.MemZero(stateBuffer);
			SecureMemory.MemZero(plainBuffer);
			TryReturnBuffers(cipherBuffer, plainBuffer);
		}
	}

	/// <summary>
	/// Asynchronously reads data from a stream until the specified number of bytes
	/// have been read or the end of the stream is reached.
	/// </summary>
	/// <param name="stream">The stream to read from.</param>
	/// <param name="buffer">The buffer to fill with data read from the stream.</param>
	/// <param name="offset">The zero-based byte offset in <paramref name="buffer"/> at which to begin
	/// storing the data read from the stream.</param>
	/// <param name="count">The maximum number of bytes to read from the stream.</param>
	/// <param name="ct">A token that can be used to cancel the asynchronous operation.
	/// Defaults to <see cref="CancellationToken.None"/>.</param>
	/// <returns>A <see cref="Task{TResult}"/> that represents the asynchronous read operation.
	/// The result is the total number of bytes read into the buffer. This can be less than
	/// <paramref name="count"/> if the end of the stream is reached before <paramref name="count"/>
	/// bytes are read.</returns>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="stream"/> or <paramref name="buffer"/> is null.</exception>
	/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="offset"/> or <paramref name="count"/>
	/// is negative, or if <paramref name="offset"/> plus <paramref name="count"/> is greater than
	/// the length of <paramref name="buffer"/>.</exception>
	/// <exception cref="OperationCanceledException">Thrown if the operation is canceled via the
	/// <paramref name="ct"/>.</exception>

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
	/// Synchronously reads data from a stream until the specified number of bytes
	/// have been read or the end of the stream is reached.
	/// </summary>
	/// <param name="stream">The stream to read from.</param>
	/// <param name="buffer">The buffer to fill with data read from the stream.</param>
	/// <param name="offset">The zero-based byte offset in <paramref name="buffer"/> at which to begin
	/// storing the data read from the stream.</param>
	/// <param name="count">The maximum number of bytes to read from the stream.</param>
	/// <returns>The total number of bytes read into the buffer. This can be less than
	/// <paramref name="count"/> if the end of the stream is reached before <paramref name="count"/>
	/// bytes are read.</returns>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="stream"/> or <paramref name="buffer"/> is null.</exception>
	/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="offset"/> or <paramref name="count"/>
	/// is negative, or if <paramref name="offset"/> plus <paramref name="count"/> is greater than
	/// the length of <paramref name="buffer"/>.</exception>

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

	/// <summary>
	/// Asynchronously encrypts data from the <paramref name="input"/> stream using a key
	/// stored in <see cref="SecureMemory{T}"/> and writes the ciphertext to the <paramref name="output"/> stream.
	/// </summary>
	/// <param name="input">The readable stream containing plaintext to encrypt.</param>
	/// <param name="output">The writable stream where ciphertext will be written.</param>
	/// <param name="key">
	/// A secure memory buffer containing the secret key. It is critical that this buffer is disposed properly
	/// to ensure the key is wiped from memory.
	/// </param>
	/// <param name="cancellationToken">Optional token to cancel the asynchronous operation.</param>
	/// <returns>A task representing the asynchronous encryption process.</returns>
	/// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
	/// <exception cref="ObjectDisposedException">Thrown if the secure key has already been disposed.</exception>
	/// <exception cref="OperationCanceledException">Thrown if the operation is canceled.</exception>
	/// <remarks>
	/// <para>
	/// This overload offers identical functionality to
	/// <see cref="EncryptAsync(Stream, Stream, ReadOnlyMemory{byte}, CancellationToken)"/>,
	/// but uses a <see cref="SecureMemory{T}"/> buffer to enhance key security during runtime.
	/// </para>
	/// <para>
	/// Using secure memory reduces the risk of sensitive data being captured in memory dumps
	/// or accessed by unauthorized code.
	/// </para>
	/// </remarks>
	public static async Task EncryptAsync(
		Stream input,
		Stream output,
		SecureMemory<byte> key,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(key, nameof(key));
		await EncryptAsync(input, output, key.AsMemory(), cancellationToken).ConfigureAwait(false);
	}

	/// <summary>
	/// Attempts to return a rented buffer back to the shared <see cref="ArrayPool{T}"/> instance.
	/// Any exceptions that occur during the return process are caught and ignored to prevent
	/// potential issues during cleanup.
	/// </summary>
	/// <param name="buffer">The buffer to return to the pool. If <paramref name="buffer"/> is null,
	/// this method does nothing.</param>

	private static void TryReturnBuffer(byte[]? buffer)
	{
		try
		{
			if (buffer != null)
				ArrayPool<byte>.Shared.Return(buffer);
		}
		catch
		{
			// Handle any exceptions that may occur during buffer return
			// This is a no-op in this case, but you may want to log the error or take other actions.
		}
	}

	/// <summary>
	/// Attempts to return two rented buffers back to the shared <see cref="ArrayPool{T}"/> instance.
	/// This is a convenience method for returning multiple buffers. Any exceptions that occur
	/// during the return process are caught and ignored.
	/// </summary>
	/// <param name="b1">The first buffer to return to the pool. Can be null.</param>
	/// <param name="b2">The second buffer to return to the pool. Can be null.</param>

	private static void TryReturnBuffers(byte[]? b1, byte[]? b2)
	{
		TryReturnBuffer(b1);
		TryReturnBuffer(b2);
	}

	/// <summary>
	/// Asynchronously decrypts data from the <paramref name="input"/> stream and writes the plaintext
	/// to the <paramref name="output"/> stream, verifying integrity using XChaCha20-Poly1305.
	/// </summary>
	/// <param name="input">
	/// A readable stream containing encrypted data. The stream must begin with the header
	/// produced during encryption.
	/// </param>
	/// <param name="output">The writable stream where decrypted plaintext will be written.</param>
	/// <param name="key">
	/// The secret key used for decryption. It must match the key used during encryption.
	/// </param>
	/// <param name="cancellationToken">Optional token to cancel the asynchronous operation.</param>
	/// <returns>A task representing the asynchronous decryption process.</returns>
	/// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
	/// <exception cref="EndOfStreamException">
	/// Thrown if the stream ends unexpectedly or the final tag is never reached.
	/// </exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if the integrity check fails on any chunk (i.e., authentication tag mismatch).
	/// </exception>
	/// <exception cref="OperationCanceledException">Thrown if the operation is canceled.</exception>
	/// <remarks>
	/// <para>
	/// The decryption process begins by reading the stream header, which includes a nonce required
	/// to initialize the decryption state. Each encrypted chunk is then read, authenticated,
	/// and decrypted in order.
	/// </para>
	/// <para>
	/// If any chunk fails authentication, a <see cref="LibSodiumException"/> is thrown and no plaintext
	/// is written for that chunk. If the stream ends before encountering a chunk tagged as
	/// <see cref="CryptoSecretStreamTag.Final"/>, an <see cref="EndOfStreamException"/> is thrown.
	/// </para>
	/// <para>
	/// This method uses pooled buffers and zeroes out internal state after use to reduce memory leakage risks.
	/// Input and output streams are not closed automatically.
	/// </para>
	/// </remarks>
	public static async Task DecryptAsync(
		Stream input,
		Stream output,
		ReadOnlyMemory<byte> key,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(input, nameof(input));
		ArgumentNullException.ThrowIfNull(output, nameof(output));
		ArgumentNullException.ThrowIfNull(key, nameof(key));
		byte[]? cipherBuffer = null;
		byte[]? plainBuffer = null;
		try
		{
			cipherBuffer = ArrayPool<byte>.Shared.Rent(CipherChunkSize);
			plainBuffer = ArrayPool<byte>.Shared.Rent(PlainChunkSize);
		}
		catch
		{
			TryReturnBuffers(cipherBuffer, plainBuffer);
			throw;
		}

		byte[] stateBuffer = new byte[CryptoSecretStream.StateLen];
		byte[] headerBuffer = new byte[CryptoSecretStream.HeaderLen];

		try
		{
			// Read header
			await input.ReadExactlyAsync(headerBuffer).ConfigureAwait(false);

			CryptoSecretStream.InitializeDecryption(stateBuffer, headerBuffer, key.Span);
			bool tagFinalReached = false;

			while (true)
			{
				int chunkLength = await FillBufferAsync(input, cipherBuffer, 0, CipherChunkSize, cancellationToken).ConfigureAwait(false);
				if (chunkLength == 0)
				{
					if (!tagFinalReached)
					{
						throw new EndOfStreamException("Incomplete stream: Final tag not reached.");
					}
					break;
				}

				CryptoSecretStreamTag tag;
				var plainLen = CryptoSecretStream.DecryptChunk(
					stateBuffer,
					plainBuffer,
					out tag,
					cipherBuffer.AsSpan(0, chunkLength)
				).Length;

				await output.WriteAsync(plainBuffer.AsMemory(0, plainLen), cancellationToken).ConfigureAwait(false);

				if (tag == CryptoSecretStreamTag.Final)
				{
					tagFinalReached = true;
					break;
				}
			}
		}
		finally
		{
			SecureMemory.MemZero(stateBuffer);
			SecureMemory.MemZero(plainBuffer);
			TryReturnBuffers(cipherBuffer, plainBuffer);
		}
	}

	/// <summary>
	/// Asynchronously decrypts data from the <paramref name="input"/> stream using a key
	/// stored in <see cref="SecureMemory{T}"/>, and writes the plaintext to the <paramref name="output"/> stream.
	/// </summary>
	/// <param name="input">
	/// A readable stream containing the encrypted data. The stream must begin with the encryption header.
	/// </param>
	/// <param name="output">The writable stream where the decrypted plaintext will be written.</param>
	/// <param name="key">
	/// A secure memory buffer containing the decryption key. This must match the key used to encrypt the stream.
	/// </param>
	/// <param name="cancellationToken">Optional token to cancel the asynchronous operation.</param>
	/// <returns>A task representing the asynchronous decryption process.</returns>
	/// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
	/// <exception cref="ObjectDisposedException">Thrown if the secure key has already been disposed.</exception>
	/// <exception cref="EndOfStreamException">Thrown if the stream ends before the final tag is reached.</exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if the integrity check fails (e.g., if the ciphertext has been tampered with).
	/// </exception>
	/// <exception cref="OperationCanceledException">Thrown if the operation is canceled.</exception>
	/// <remarks>
	/// <para>
	/// This overload behaves identically to
	/// <see cref="DecryptAsync(Stream, Stream, ReadOnlyMemory{byte}, CancellationToken)"/>,
	/// but uses a <see cref="SecureMemory{T}"/> buffer for enhanced runtime key protection.
	/// </para>
	/// <para>
	/// The key is securely wiped from memory once decryption is complete. Stream lifetime is not managed automatically.
	/// </para>
	/// </remarks>

	public static async Task DecryptAsync(
		Stream input,
		Stream output,
		SecureMemory<byte> key,
		CancellationToken cancellationToken = default)
	{
		await DecryptAsync(input, output, key.AsMemory(), cancellationToken).ConfigureAwait(false);
	}

	/// <summary>
	/// Synchronously encrypts data from the <paramref name="input"/> stream and writes the ciphertext
	/// to the <paramref name="output"/> stream using the XChaCha20-Poly1305 algorithm.
	/// </summary>
	/// <param name="input">The readable stream containing plaintext to encrypt.</param>
	/// <param name="output">The writable stream where ciphertext will be written.</param>
	/// <param name="key">
	/// The encryption key. Must be securely generated and exactly 32 bytes long for XChaCha20-Poly1305.
	/// </param>
	/// <exception cref="ArgumentException">Thrown if the key is invalid.</exception>
	/// <exception cref="EndOfStreamException">Thrown if the input stream ends unexpectedly.</exception>
	/// <remarks>
	/// <para>
	/// This method performs stream encryption in-place and blocks the calling thread until completion.
	/// It is suitable for scenarios where asynchronous patterns are not required or not supported.
	/// </para>
	/// <para>
	/// The input is processed in chunks of <see cref="PlainChunkSize"/> bytes. Each chunk is encrypted
	/// and authenticated before being written to the output stream. A cryptographic header is written at the beginning,
	/// and a final tag is written after the last chunk.
	/// </para>
	/// <para>
	/// All internal buffers are zeroed after use, and pooled memory is returned. The input and output
	/// streams are not closed or disposed automatically.
	/// </para>
	/// </remarks>


	public static void Encrypt(Stream input, Stream output, ReadOnlySpan<byte> key)
	{
		ArgumentNullException.ThrowIfNull(input, nameof(input));
		ArgumentNullException.ThrowIfNull(output, nameof(output));
		byte[]? cipherBuffer = null;
		byte[]? plainBuffer = null;
		try
		{
			cipherBuffer = ArrayPool<byte>.Shared.Rent(CipherChunkSize);
			plainBuffer = ArrayPool<byte>.Shared.Rent(PlainChunkSize);
		}
		catch
		{
			TryReturnBuffers(cipherBuffer, plainBuffer);
			throw;
		}

		Span<byte> stateBuffer = stackalloc byte[CryptoSecretStream.StateLen];
		Span<byte> headerBuffer = stackalloc byte[CryptoSecretStream.HeaderLen];

		try
		{
			CryptoSecretStream.InitializeEncryption(stateBuffer, headerBuffer, key);
			output.Write(headerBuffer);

			int bytesRead = 0;
			bool endOfStream = false;

			while (!endOfStream)
			{
				bytesRead = FillBuffer(input, plainBuffer, 0, PlainChunkSize);
				endOfStream = bytesRead < PlainChunkSize;

				var tag = endOfStream ? CryptoSecretStreamTag.Final : CryptoSecretStreamTag.Message;

				var ciphertext = CryptoSecretStream.EncryptChunk(
					stateBuffer,
					cipherBuffer,
					plainBuffer.AsSpan(0, bytesRead),
					tag
				);

				output.Write(ciphertext);

			}
		}
		finally
		{
			SecureMemory.MemZero(stateBuffer);
			SecureMemory.MemZero(plainBuffer);
			TryReturnBuffers(cipherBuffer, plainBuffer);
		}
	}

	/// <summary>
	/// Synchronously encrypts data from the <paramref name="input"/> stream using a secure key,
	/// and writes the ciphertext to the <paramref name="output"/> stream.
	/// </summary>
	/// <param name="input">The readable stream containing plaintext to encrypt.</param>
	/// <param name="output">The writable stream where ciphertext will be written.</param>
	/// <param name="key">
	/// A <see cref="SecureMemory{T}"/> buffer containing the encryption key. It must be 32 bytes in size,
	/// and will be securely wiped from memory after use.
	/// </param>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/>, <paramref name="input"/>, or <paramref name="output"/> is null.</exception>
	/// <exception cref="ObjectDisposedException">Thrown if the key has already been disposed.</exception>
	/// <exception cref="ArgumentException">Thrown if the key is invalid (wrong length).</exception>
	/// <remarks>
	/// <para>
	/// This method is functionally equivalent to <see cref="Encrypt(Stream, Stream, ReadOnlySpan{byte})"/>,
	/// but accepts the encryption key wrapped in <see cref="SecureMemory{T}"/> for added in-memory protection.
	/// </para>
	/// <para>
	/// This improves resistance to key leakage through memory inspection, especially in long-lived processes.
	/// </para>
	/// </remarks>
	public static void Encrypt(Stream input, Stream output, SecureMemory<byte> key)
	{
		Encrypt(input, output, key.AsSpan());
	}

	/// <summary>
	/// Synchronously decrypts data from the <paramref name="input"/> stream and writes the plaintext
	/// to the <paramref name="output"/> stream, verifying each chunk's authenticity using XChaCha20-Poly1305.
	/// </summary>
	/// <param name="input">
	/// The readable stream containing encrypted data. The stream must begin with the encryption header
	/// produced during the corresponding encryption process.
	/// </param>
	/// <param name="output">The writable stream where decrypted plaintext will be written.</param>
	/// <param name="key">
	/// The secret decryption key. It must match the key used to encrypt the stream and be exactly 32 bytes long.
	/// </param>
	/// <exception cref="ArgumentException">Thrown if the key is invalid.</exception>
	/// <exception cref="EndOfStreamException">
	/// Thrown if the stream ends before the <see cref="CryptoSecretStreamTag.Final"/> tag is reached,
	/// indicating an incomplete or truncated stream.
	/// </exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if authentication fails, indicating the ciphertext has been tampered with or the wrong key was used.
	/// </exception>
	/// <remarks>
	/// <para>
	/// This method processes the encrypted stream in chunks, validating each chunk before decrypting it.
	/// If authentication fails, a <see cref="LibSodiumException"/> is thrown and the decrypted output is invalidated.
	/// </para>
	/// <para>
	/// The stream must start with a header containing the nonce and metadata necessary for decryption.
	/// This header is automatically consumed at the beginning of the stream.
	/// </para>
	/// <para>
	/// All internal buffers are zeroed after use. The input and output streams are not closed automatically.
	/// </para>
	/// </remarks>

	public static void Decrypt(Stream input, Stream output, ReadOnlySpan<byte> key)
	{
		byte[]? cipherBuffer = null;
		byte[]? plainBuffer = null;
		try
		{
			cipherBuffer = ArrayPool<byte>.Shared.Rent(CipherChunkSize);
			plainBuffer = ArrayPool<byte>.Shared.Rent(PlainChunkSize);
		}
		catch
		{
			TryReturnBuffers(cipherBuffer, plainBuffer);
			throw;
		}

		Span<byte> stateBuffer = stackalloc byte[CryptoSecretStream.StateLen];
		Span<byte> headerBuffer = stackalloc byte[CryptoSecretStream.HeaderLen];

		try
		{
			input.ReadExactly(headerBuffer);

			CryptoSecretStream.InitializeDecryption(stateBuffer, headerBuffer, key);

			bool tagFinalReached = false;

			while (true)
			{
				int chunkLength = FillBuffer(input, cipherBuffer, 0, CipherChunkSize);
				if (chunkLength == 0)
				{
					if (!tagFinalReached)
						throw new EndOfStreamException("Incomplete stream: Final tag was not reached.");
					break;
				}

				CryptoSecretStreamTag tag;
				var clearSpan = CryptoSecretStream.DecryptChunk(
					stateBuffer,
					plainBuffer,
					out tag,
					cipherBuffer.AsSpan(0, chunkLength)
				);

				output.Write(clearSpan);

				if (tag == CryptoSecretStreamTag.Final)
				{
					tagFinalReached = true;
					break;
				}
			}
		}
		finally
		{
			SecureMemory.MemZero(stateBuffer);
			SecureMemory.MemZero(plainBuffer);
			TryReturnBuffers(cipherBuffer, plainBuffer);
		}
	}

	/// <summary>
	/// Synchronously decrypts data from the <paramref name="input"/> stream using a key stored in secure memory,
	/// and writes the plaintext to the <paramref name="output"/> stream.
	/// </summary>
	/// <param name="input">
	/// The stream containing encrypted data. It must begin with the secret stream header written during encryption.
	/// </param>
	/// <param name="output">The stream where decrypted plaintext will be written.</param>
	/// <param name="key">
	/// A <see cref="SecureMemory{T}"/> buffer containing the decryption key. This key must match the one used to encrypt the stream.
	/// </param>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/>, <paramref name="output"/>, or <paramref name="key"/> is null.</exception>
	/// <exception cref="ObjectDisposedException">Thrown if the secure memory key has already been disposed.</exception>
	/// <exception cref="EndOfStreamException">Thrown if the stream ends before the <see cref="CryptoSecretStreamTag.Final"/> tag is encountered.</exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if the authentication of a chunk fails, which indicates tampering or a mismatched key.
	/// </exception>
	/// <remarks>
	/// <para>
	/// This method behaves identically to <see cref="Decrypt(Stream, Stream, ReadOnlySpan{byte})"/>,
	/// but uses a secure memory buffer for enhanced key confidentiality.
	/// </para>
	/// <para>
	/// The decryption header is consumed automatically at the beginning of the stream. Chunks are processed sequentially,
	/// and any failure in tag verification will cause decryption to halt with an exception.
	/// </para>
	/// <para>
	/// Internal buffers are cleared and returned to the pool after use. The input and output streams remain open.
	/// </para>
	/// </remarks>


	public static void Decrypt(Stream input, Stream output, SecureMemory<byte> key)
	{
		Decrypt(input, output, key.AsReadOnlySpan());
	}
}

```

# 🧪 SecretStreamTests.cs

```csharp
﻿using System.Text;

namespace LibSodium.Tests;

public class SecretStreamTests
{
	private static byte[] GenerateRandomBytes(int length)
	{
		var bytes = new byte[length];
		Random.Shared.NextBytes(bytes);
		return bytes;
	}


	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(SecretStream.PlainChunkSize - 1)]
	[Arguments(SecretStream.PlainChunkSize)]
	[Arguments(SecretStream.PlainChunkSize + 1)]
	[Arguments(SecretStream.PlainChunkSize * 2 - 1)]
	[Arguments(SecretStream.PlainChunkSize * 2)]
	[Arguments(SecretStream.PlainChunkSize * 2 + 1)]
	public async Task EncryptAndDecryptAsync_Success(int plaintextLen)
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		var plaintext = GenerateRandomBytes(plaintextLen);
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		await SecretStream.EncryptAsync(input, encryptedOutput, key);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();
		await SecretStream.DecryptAsync(encryptedOutput, decryptedOutput, key);
		decryptedOutput.ToArray().ShouldBe(plaintext);
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(SecretStream.PlainChunkSize - 1)]
	[Arguments(SecretStream.PlainChunkSize)]
	[Arguments(SecretStream.PlainChunkSize + 1)]
	[Arguments(SecretStream.PlainChunkSize * 2 - 1)]
	[Arguments(SecretStream.PlainChunkSize * 2)]
	[Arguments(SecretStream.PlainChunkSize * 2 + 1)]
	public void EncryptAndDecrypt_Sync_Success(int plaintextLen)
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		var plaintext = GenerateRandomBytes(plaintextLen); // 64KB data
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		SecretStream.Encrypt(input, encryptedOutput, key);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();
		SecretStream.Decrypt(encryptedOutput, decryptedOutput, key);

		decryptedOutput.ToArray().ShouldBe(plaintext);
	}

	[Test]
	public async Task EncryptAsync_Throws_WithInvalidKey()
	{
		var invalidKey = GenerateRandomBytes(CryptoSecretStream.KeyLen - 1);

		using var input = new MemoryStream();
		using var output = new MemoryStream();

		await AssertLite.ThrowsAsync<ArgumentException>(() => SecretStream.EncryptAsync(input, output, invalidKey));

	}

	[Test]
	public async Task DecryptAsync_Throws_WithInvalidKey()
	{
		var validKey = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(validKey);

		var invalidKey = GenerateRandomBytes(CryptoSecretStream.KeyLen);

		var plaintext = GenerateRandomBytes(64 * 1024);
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		await SecretStream.EncryptAsync(input, encryptedOutput, validKey);

		encryptedOutput.Position = 0;
		using var decryptedOutput = new MemoryStream();

		await AssertLite.ThrowsAsync<LibSodiumException>(() => SecretStream.DecryptAsync(encryptedOutput, decryptedOutput, invalidKey));
	}

	[Test]
	public void Encrypt_Throws_WithNullInput()
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		using var output = new MemoryStream();

		AssertLite.Throws<ArgumentNullException>(() => SecretStream.Encrypt(null!, output, key));
	}

	[Test]
	public void Decrypt_Throws_WithTamperedCiphertext()
	{
		var key = new byte[CryptoSecretStream.KeyLen];
		CryptoSecretStream.GenerateKey(key);

		var plaintext = GenerateRandomBytes(64 * 1024);
		using var input = new MemoryStream(plaintext);
		using var encryptedOutput = new MemoryStream();

		SecretStream.Encrypt(input, encryptedOutput, key);
		var ciphertext = encryptedOutput.ToArray();
		ciphertext[CryptoSecretStream.HeaderLen + 10] ^= 0xFF; // Tamper with ciphertext

		using var tamperedInput = new MemoryStream(ciphertext);
		using var decryptedOutput = new MemoryStream();

		AssertLite.Throws<LibSodiumException>(() => SecretStream.Decrypt(tamperedInput, decryptedOutput, key));
	}

	[Test]
	public void Example()
	{
		Span<byte> key = stackalloc byte[32];
		RandomGenerator.Fill(key);

		const string hello = "Hello LibSodium.Net!";
		var helloData = Encoding.UTF8.GetBytes(hello);

		using var plaintextStream = new MemoryStream();
		using var ciphertextStream = new MemoryStream();
		using var decryptedStream = new MemoryStream();

		plaintextStream.Write(helloData);
		plaintextStream.Position = 0;

		SecretStream.Encrypt(plaintextStream, ciphertextStream, key);
		ciphertextStream.Position = 0;
		SecretStream.Decrypt(ciphertextStream, decryptedStream, key);
		decryptedStream.Position = 0;

		var isWorking = decryptedStream.ToArray().SequenceEqual(helloData);

		isWorking.ShouldBeTrue();

	}
}

```

