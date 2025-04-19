using System;
using System.Security.Cryptography;
using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides high-level access to the XChaCha20-Poly1305 AEAD construction from Libsodium.
	/// </summary>
	/// <remarks>
	/// This class supports both combined and detached modes of authenticated encryption.
	/// It also supports automatic nonce generation when not provided explicitly.
	/// </remarks>
	public static class XChaCha20Poly1305
	{
		/// <summary>
		/// The length, in bytes, of a valid key.
		/// </summary>
		public const int KeyLen = Native.CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

		/// <summary>
		/// The length, in bytes, of a valid nonce.
		/// </summary>
		public const int NonceLen = Native.CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

		/// <summary>
		/// The length, in bytes, of the authentication tag (MAC).
		/// </summary>
		public const int MacLen = Native.CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

		/// <summary>
		/// Encrypts and authenticates a plaintext using XChaCha20-Poly1305 in detached mode, generating a random nonce.
		/// </summary>
		/// <param name="ciphertext">The buffer to write the resulting nonce and ciphertext into.</param>
		/// <param name="mac">The buffer to write the authentication tag (MAC) into.</param>
		/// <param name="plaintext">The input data to encrypt.</param>
		/// <param name="key">The 32-byte encryption key.</param>
		/// <param name="aad">Optional additional data to authenticate but not encrypt.</param>
		/// <returns>A slice of <paramref name="ciphertext"/> containing the nonce followed by the ciphertext.</returns>
		/// <exception cref="ArgumentException">Thrown when buffers are too small or key length is invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when encryption fails internally.</exception>
		internal static Span<byte> EncryptDetached(Span<byte> ciphertext, Span<byte> mac, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad = default)
		{
			if (ciphertext.Length < plaintext.Length + NonceLen) throw new ArgumentException("Ciphertext buffer too small");
			var nonce = ciphertext.Slice(0, NonceLen);
			RandomGenerator.Fill(nonce);
			var cipher = ciphertext.Slice(NonceLen);
			EncryptDetached(cipher, mac, plaintext, key, aad, nonce);
			return ciphertext.Slice(0, plaintext.Length + NonceLen);
		}

		/// <summary>
		/// Encrypts and authenticates a plaintext using XChaCha20-Poly1305 in detached mode with a provided nonce.
		/// </summary>
		/// <param name="ciphertext">The buffer to write the ciphertext into.</param>
		/// <param name="mac">The buffer to write the authentication tag (MAC) into.</param>
		/// <param name="plaintext">The input data to encrypt.</param>
		/// <param name="key">The 32-byte encryption key.</param>
		/// <param name="aad">Optional additional data to authenticate but not encrypt.</param>
		/// <param name="nonce">The 24-byte nonce.</param>
		/// <returns>A slice of <paramref name="ciphertext"/> with the encrypted data.</returns>
		/// <exception cref="ArgumentException">Thrown when inputs do not match expected lengths.</exception>
		/// <exception cref="LibSodiumException">Thrown when encryption fails internally.</exception>
		internal static Span<byte> EncryptDetached(Span<byte> ciphertext, Span<byte> mac, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce)
		{
			if (key.Length != KeyLen) throw new ArgumentException($"Key must be {KeyLen} bytes");
			if (nonce.Length != NonceLen) throw new ArgumentException($"Nonce must be {NonceLen} bytes");
			if (mac.Length != MacLen) throw new ArgumentException($"MAC must be {MacLen} bytes");
			if (ciphertext.Length < plaintext.Length) throw new ArgumentException("Ciphertext buffer too small");

			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
				ciphertext,
				mac,
				out ulong _,
				plaintext,
				(ulong)plaintext.Length,
				aad,
				(ulong)aad.Length,
				nsec: IntPtr.Zero,
				nonce,
				key
			);
			if (rc != 0) throw new LibSodiumException("Detached encryption failed.");
			return ciphertext.Slice(0, plaintext.Length);
		}

		/// <summary>
		/// Decrypts a ciphertext with an authentication tag using detached mode.
		/// </summary>
		/// <param name="plaintext">The buffer to write the decrypted data.</param>
		/// <param name="ciphertext">The encrypted data.</param>
		/// <param name="key">The decryption key.</param>
		/// <param name="mac">The authentication tag (MAC).</param>
		/// <param name="additionalData">Optional additional authenticated data.</param>
		/// <param name="nonce">The nonce used during encryption.</param>
		/// <returns>A slice of <paramref name="plaintext"/> with the decrypted data.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when MAC verification fails or decryption fails.</exception>
		internal static Span<byte> DecryptDetached(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> additionalData, ReadOnlySpan<byte> nonce)
		{
			if (key.Length != KeyLen) throw new ArgumentException($"Key must be {KeyLen} bytes");
			if (nonce.Length != NonceLen) throw new ArgumentException($"Nonce must be {NonceLen} bytes");
			if (mac.Length != MacLen) throw new ArgumentException($"MAC must be {MacLen} bytes");
			if (plaintext.Length < ciphertext.Length) throw new ArgumentException("Plaintext buffer too small");

			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
				plaintext, 
				nsec: IntPtr.Zero,
				ciphertext,
				(ulong)ciphertext.Length,
				mac,
				additionalData,
				(ulong)additionalData.Length,
				nonce,
				key
			);
			if (rc != 0) throw new LibSodiumException("Detached decryption failed or MAC verification failed.");
			return plaintext.Slice(0, ciphertext.Length);
		}

		/// <summary>
		/// Decrypts a ciphertext with an authentication tag using detached mode.
		/// </summary>
		/// <param name="plaintext">The buffer to write the decrypted data.</param>
		/// <param name="ciphertext">The encrypted data.</param>
		/// <param name="key">The decryption key.</param>
		/// <param name="mac">The authentication tag (MAC).</param>
		/// <param name="additionalData">Optional additional authenticated data.</param>
		/// <returns>A slice of <paramref name="plaintext"/> with the decrypted data.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when MAC verification fails or decryption fails.</exception>
		internal static Span<byte> DecryptDetached(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> additionalData)
		{
			if (ciphertext.Length < NonceLen) throw new ArgumentException("Ciphertext too short", nameof(ciphertext));
			if (plaintext.Length < ciphertext.Length - NonceLen) throw new ArgumentException("Plaintext buffer too small");
			var nonce = ciphertext.Slice(0, NonceLen);
			var cipher = ciphertext.Slice(NonceLen);
			return DecryptDetached(plaintext, cipher, key, mac, additionalData, nonce);
		}

		/// <summary>
		/// Encrypts and authenticates plaintext using XChaCha20-Poly1305 in combined mode (MAC is appended).
		/// </summary>
		/// <param name="ciphertext">The buffer to write the resulting ciphertext and MAC into.</param>
		/// <param name="plaintext">The data to encrypt.</param>
		/// <param name="key">The encryption key.</param>
		/// <param name="aad">The authenticated additional data</param>
		/// <param name="nonce">The nonce to use for encryption.</param>
		/// <returns>A slice of <paramref name="ciphertext"/> containing the ciphertext and MAC.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when encryption fails internally.</exception>
		internal static Span<byte> EncryptCombined(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce)
		{
			if (ciphertext.Length < plaintext.Length + MacLen) throw new ArgumentException("Ciphertext buffer too small");

			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_aead_xchacha20poly1305_ietf_encrypt(
				ciphertext,
				out ulong clen,
				plaintext,
				(ulong)plaintext.Length,
				aad,
				(ulong) aad.Length,
				nsec: IntPtr.Zero,
				nonce,
				key
			);
			if (rc != 0) throw new LibSodiumException("Encryption failed.");
			return ciphertext.Slice(0, plaintext.Length + MacLen);
		}

		/// <summary>
		/// Encrypts using combined mode and prepends a randomly generated nonce.
		/// </summary>
		/// <param name="ciphertext">The buffer to store [nonce | ciphertext | MAC].</param>
		/// <param name="plaintext">The data to encrypt.</param>
		/// <param name="key">The encryption key.</param>
		/// <param name="aad">The authenticated additional data</param>
		/// <returns>A slice of <paramref name="ciphertext"/> including the nonce and MAC.</returns>
		/// <exception cref="ArgumentException">Thrown when the buffer is too small or key length is invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when encryption fails internally.</exception>
		internal static Span<byte> EncryptCombined(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad = default)
		{
			if (ciphertext.Length < plaintext.Length + MacLen + NonceLen) throw new ArgumentException("Ciphertext buffer too small");
			var nonce = ciphertext.Slice(0, NonceLen);
			RandomGenerator.Fill(nonce);
			var cipher = ciphertext.Slice(NonceLen);
			EncryptCombined(cipher, plaintext, key, aad, nonce);
			return ciphertext.Slice(0, plaintext.Length + MacLen + NonceLen);
		}

		/// <summary>
		/// Decrypts ciphertext in combined mode using the provided nonce.
		/// </summary>
		/// <param name="plaintext">The buffer to write the decrypted data.</param>
		/// <param name="ciphertext">The ciphertext including MAC.</param>
		/// <param name="key">The encryption key.</param>
		/// <param name="aad">The authenticated additional data</param>
		/// <param name="nonce">The nonce used during encryption.</param>
		/// <returns>A slice of <paramref name="plaintext"/> with the decrypted data.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when MAC verification fails or decryption fails.</exception>
		internal static Span<byte> DecryptCombined(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce)
		{
			if (plaintext.Length < ciphertext.Length - MacLen) throw new ArgumentException("Plaintext buffer too small");

			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_aead_xchacha20poly1305_ietf_decrypt(
				plaintext,
				out ulong plaintext_len,
				nsec: IntPtr.Zero,
				ciphertext,
				(ulong)ciphertext.Length,
				aad,
				(ulong) aad.Length,
				nonce,
				key
			);
			if (rc != 0) throw new LibSodiumException("Decryption failed or MAC verification failed.");
			return plaintext.Slice(0, (int)plaintext_len);
		}

		/// <summary>
		/// Decrypts combined ciphertext that includes a prepended nonce.
		/// </summary>
		/// <param name="plaintext">The buffer to write the plaintext.</param>
		/// <param name="ciphertext">The combined data [nonce | ciphertext | MAC].</param>
		/// <param name="key">The encryption key.</param>
		/// <param name="aad">The authenticated additional data</param>
		/// <returns>A slice of <paramref name="plaintext"/> containing the decrypted data.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or ciphertext is too short.</exception>
		/// <exception cref="LibSodiumException">Thrown when MAC verification fails or decryption fails.</exception>
		internal static Span<byte> DecryptCombined(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad = default)
		{
			if (ciphertext.Length < MacLen + NonceLen) throw new ArgumentException("Ciphertext too short");
			var nonce = ciphertext.Slice(0, NonceLen);
			var cipher = ciphertext.Slice(NonceLen);
			if (plaintext.Length < cipher.Length - MacLen) throw new ArgumentException("Plaintext buffer too small");
			return DecryptCombined(plaintext, cipher, key, aad, nonce);
		}

		/// <summary>
		/// Encrypts a message using XChaCha20-Poly1305. Supports combined and detached modes,
		/// with optional AAD and nonce.
		/// </summary>
		/// <param name="ciphertext">
		/// The buffer where the ciphertext will be written. It can be longer than needed.
		/// In combined mode, it must include space for the MAC and, if auto-nonce is used, the nonce as well.
		/// </param>
		/// <param name="plaintext">The message to encrypt.</param>
		/// <param name="key">The secret encryption key (32 bytes).</param>
		/// <param name="mac">
		/// Optional. If provided, the encryption is done in detached mode and the MAC is written here.
		/// Otherwise, combined mode is used.
		/// </param>
		/// <param name="aad">
		/// Optional additional authenticated data. Not encrypted, but authenticated.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided, a random nonce is generated and prepended (combined) or returned (detached).
		/// </param>
		/// <returns>
		/// The span representing the full ciphertext, including MAC and possibly nonce.
		/// </returns>

		public static Span<byte> Encrypt(
			Span<byte> ciphertext,
			ReadOnlySpan<byte> plaintext,
			ReadOnlySpan<byte> key,
			Span<byte> mac = default,
			ReadOnlySpan<byte> aad = default,
			ReadOnlySpan<byte> nonce = default)
		{
			if (mac == default)
			{
				// Combined mode
				if (nonce == default)
					return EncryptCombined(ciphertext, plaintext, key, aad);
				else
					return EncryptCombined(ciphertext, plaintext, key, aad, nonce);
			}
			else
			{
				// Detached mode
				if (nonce == default)
					return EncryptDetached(ciphertext, mac, plaintext, key, aad);
				else
					return EncryptDetached(ciphertext, mac, plaintext, key, aad, nonce);
			}
		}

		/// <summary>
		/// Decrypts a message using XChaCha20-Poly1305. Supports combined and detached modes,
		/// with optional AAD and nonce.
		/// </summary>
		/// <param name="plaintext">The buffer where the decrypted message will be written. It can be longer than needed</param>
		/// <param name="ciphertext">
		/// The encrypted message. May include MAC and nonce (combined) or exclude them (detached).
		/// </param>
		/// <param name="key">The secret decryption key (32 bytes).</param>
		/// <param name="mac">
		/// Optional. If provided, decryption is done in detached mode. If null, combined mode is used.
		/// </param>
		/// <param name="aad">
		/// Optional additional authenticated data. Must match what was used for encryption.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). Required for manual nonce mode.
		/// </param>
		/// <returns>The span representing the decrypted plaintext.</returns>
		public static Span<byte> Decrypt(
			Span<byte> plaintext,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> key,
			ReadOnlySpan<byte> mac = default,
			ReadOnlySpan<byte> aad = default,
			ReadOnlySpan<byte> nonce = default)
		{
			if (mac == default)
			{
				// Combined mode
				if (nonce == default)
					return DecryptCombined(plaintext, ciphertext, key, aad);
				else
					return DecryptCombined(plaintext, ciphertext, key, aad, nonce);
			}
			else
			{
				// Detached mode
				if (nonce == default)
					return DecryptDetached(plaintext, ciphertext, key, mac, aad);
				else
					return DecryptDetached(plaintext, ciphertext, key, mac, aad, nonce);
			}
		}

	}
}
