using LibSodium.Interop;

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
			SecureMemory<byte> key,
			Span<byte> mac = default,
			ReadOnlySpan<byte> nonce = default)
		{
			return Encrypt(ciphertext, plaintext, key.AsReadOnlySpan(), mac, nonce);
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
			SecureMemory<byte> key,
			ReadOnlySpan<byte> mac = default,
			ReadOnlySpan<byte> nonce = default)
		{
			return Decrypt(plaintext, ciphertext, key.AsReadOnlySpan(), mac, nonce);
		}
	}
}
