using LibSodium.Interop;
using System;
using System.Xml.Linq;

namespace LibSodium
{
	/// <summary>
	/// The tags used in the secret stream.
	/// </summary>
	public enum CryptoSecretStreamTag
	{
		/// <summary>
		/// The value of the tag corresponding to a regular message.
		/// </summary>
		Message = Native.CRYPTO_SECRET_STREAM_TAG_MESSAGE,
		/// <summary>
		/// The value of the tag corresponding to the final message.
		/// </summary>
		Final = Native.CRYPTO_SECRET_STREAM_TAG_FINAL,
		/// <summary>
		/// Indicates that the message marks the end of a set of messages, but not the end of the stream
		/// </summary>
		Push = Native.CRYPTO_SECRET_STREAM_TAG_PUSH,
		/// <summary>
		/// “forget” the key used to encrypt this message and the previous ones, and derive a new secret key
		/// </summary>
		Rekey = Native.CRYPTO_SECRET_STREAM_TAG_REKEY
	}

	/// <summary>
	/// The CryptoSecretStream class provides methods for performing authenticated encryption and decryption of data streams, with optional additional authenticated data. It is based on the XChaCha20-Poly1305 algorithm.
	/// </summary>
	public static class CryptoSecretStream
	{


		/// <summary>
		/// The length of the key used for encryption and decryption.
		/// </summary>
		public const int KeyLen = Native.CRYPTO_SECRET_STREAM_KEYBYTES;

		/// <summary>
		/// The length of the header used in the secret stream.
		/// </summary>
		public const int HeaderLen = Native.CRYPTO_SECRET_STREAM_HEADERBYTES;


		/// <summary>
		/// The length of the state used in the secret stream.
		/// </summary>
		public static int StateLen = Native.crypto_secretstream_xchacha20poly1305_statebytes();


		/// <summary>
		/// The length of the overhead added to each ciphertext message. This includes the authentication tag and any necessary metadata for the stream.
		/// </summary>
		public static int OverheadLen = Native.CRYPTO_SECRET_STREAM_ABYTES;


		/// <summary>
		/// Generates a random key for use with the secret stream.
		/// </summary>
		/// <param name="key">The span to write the generated key to.</param>
		/// <exception cref="ArgumentException">If the length of the key span is not equal to <see cref="KeyLen"/>.</exception>
		public static void GenerateKey(Span<byte> key)
		{
			LibraryInitializer.EnsureInitialized();
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key length must be {KeyLen} bytes.");
			}
			Native.crypto_secretstream_xchacha20poly1305_keygen(key);
		}

		/// <summary>
		/// Generates a random key for use with the secret stream.
		/// </summary>
		/// <param name="key">The span to write the generated key to.</param>
		/// <exception cref="ArgumentException">If the length of the key span is not equal to <see cref="KeyLen"/>.</exception>
		public static void GenerateKey(SecureMemory<byte> key)
		{
			GenerateKey(key.AsSpan());
		}

		/// <summary>
		/// Initializes the authenticated encryption process for a secret stream.
		/// </summary>
		/// <param name="state">The span to write the initial state to. Must be <see cref="StateLen"/> bytes long.</param>
		/// <param name="header">The span to write the stream header to. Must be <see cref="HeaderLen"/> bytes long.</param>
		/// <param name="key">The secret key to use for encryption. Must be <see cref="KeyLen"/> bytes long.</param>
		/// <exception cref="ArgumentException">If the length of the state, header, or key spans are incorrect.</exception>
		/// <exception cref="LibSodiumException">If the initialization of encryption fails.</exception>
		public static void InitializeEncryption(Span<byte> state, Span<byte> header, ReadOnlySpan<byte> key)
		{
			if (state.Length != StateLen)
			{
				throw new ArgumentException($"State length must be {StateLen} bytes.");
			}
			if (header.Length != HeaderLen)
			{
				throw new ArgumentException($"Header length must be {HeaderLen} bytes.");
			}
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key length must be {KeyLen} bytes.", nameof(key));
			}
			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_secretstream_xchacha20poly1305_init_push(state, header, key) != 0)
			{
				throw new LibSodiumException("Failed to initialize encryption.");
			};
		}

		/// <summary>
		/// Initializes the authenticated encryption process for a secret stream.
		/// </summary>
		/// <param name="state">The span to write the initial state to. Must be <see cref="StateLen"/> bytes long.</param>
		/// <param name="header">The span to write the stream header to. Must be <see cref="HeaderLen"/> bytes long.</param>
		/// <param name="key">The secret key to use for encryption. Must be <see cref="KeyLen"/> bytes long.</param>
		/// <exception cref="ArgumentException">If the length of the state, header, or key spans are incorrect.</exception>
		/// <exception cref="LibSodiumException">If the initialization of encryption fails.</exception>
		public static void InitializeEncryption(SecureMemory<byte> state, Span<byte> header, SecureMemory<byte> key)
		{
			InitializeEncryption(state.AsSpan(), header, key.AsReadOnlySpan());
		}

		/// <summary>
		/// Encrypts and authenticates a block of data using the secret stream with additional authenticated data (AAD).
		/// </summary>
		/// <param name="state">The current state of the secret stream. Must be <see cref="StateLen"/> bytes long.</param>
		/// <param name="ciphertext">The span to write the encrypted and authenticated data to. Must have a length of at least <paramref name="cleartext"/>.<see cref="Span{T}.Length"/> + <see cref="OverheadLen"/>.</param>
		/// <param name="cleartext">The data to encrypt.</param>
		/// <param name="tag">The tag to associate with this message.</param>
		/// <param name="additionalData">Additional data that is cryptographically incorporated during the calculation of the authentication tag for the ciphertext. This data is authenticated but not encrypted.</param>
		/// <returns>A <see cref="Span{T}"/> representing the encrypted and authenticated data written to <paramref name="ciphertext"/>.</returns>
		/// <exception cref="ArgumentException">If the length of the state or ciphertext spans are incorrect.</exception>
		/// <exception cref="LibSodiumException">If the encryption of the chunk fails.</exception>
		public static Span<byte> EncryptChunk(
			Span<byte> state,
			Span<byte> ciphertext,
			ReadOnlySpan<byte> cleartext,
			CryptoSecretStreamTag tag,
			ReadOnlySpan<byte> additionalData = default)
		{
			if (state.Length != StateLen)
			{
				throw new ArgumentException($"State length must be {StateLen} bytes.", nameof(state));
			}
			if (ciphertext.Length < cleartext.Length + OverheadLen)
			{
				throw new ArgumentException($"Ciphertext length must be at least {cleartext.Length + OverheadLen} bytes.", nameof(ciphertext));
			}
			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_secretstream_xchacha20poly1305_push(state, ciphertext, out var cipherLen, cleartext, (ulong)cleartext.Length, additionalData, (ulong)additionalData.Length, (byte)tag) != 0)
			{
				throw new LibSodiumException("Failed to encrypt chunk.");
			}
			return ciphertext.Slice(0, (int)cipherLen);
		}

		/// <summary>
		/// Encrypts and authenticates a block of data using the secret stream with additional authenticated data (AAD).
		/// </summary>
		/// <param name="state">The current state of the secret stream. Must be <see cref="StateLen"/> bytes long.</param>
		/// <param name="ciphertext">The span to write the encrypted and authenticated data to. Must have a length of at least <paramref name="cleartext"/>.<see cref="Span{T}.Length"/> + <see cref="OverheadLen"/>.</param>
		/// <param name="cleartext">The data to encrypt.</param>
		/// <param name="tag">The tag to associate with this message.</param>
		/// <param name="additionalData">Additional data that is cryptographically incorporated during the calculation of the authentication tag for the ciphertext. This data is authenticated but not encrypted.</param>
		/// <returns>A <see cref="Span{T}"/> representing the encrypted and authenticated data written to <paramref name="ciphertext"/>.</returns>
		/// <exception cref="ArgumentException">If the length of the state or ciphertext spans are incorrect.</exception>
		/// <exception cref="LibSodiumException">If the encryption of the chunk fails.</exception>
		public static Span<byte> EncryptChunk(
			SecureMemory<byte> state,
			Span<byte> ciphertext,
			ReadOnlySpan<byte> cleartext,
			CryptoSecretStreamTag tag,
			ReadOnlySpan<byte> additionalData = default)
		{
			return EncryptChunk(state.AsSpan(), ciphertext, cleartext, tag, additionalData);
		}

		/// <summary>
		/// Initializes the authenticated decryption process for a secret stream.
		/// </summary>
		/// <param name="state">The span to write the initial state to. Must be <see cref="StateLen"/> bytes long.</param>
		/// <param name="header">The stream header received from the sender. Must be <see cref="HeaderLen"/> bytes long.</param>
		/// <param name="key">The secret key used for encryption. Must be <see cref="KeyLen"/> bytes long.</param>
		/// <exception cref="ArgumentException">If the length of the state, header, or key spans are incorrect.</exception>
		/// <exception cref="LibSodiumException">If the initialization of decryption fails, likely due to an incorrect header or key.</exception>
		public static void InitializeDecryption(Span<byte> state, ReadOnlySpan<byte> header, ReadOnlySpan<byte> key)
		{
			if (state.Length != StateLen)
			{
				throw new ArgumentException($"State length must be {StateLen} bytes.", nameof(state));
			}
			if (header.Length != HeaderLen)
			{
				throw new ArgumentException($"Header length must be {HeaderLen} bytes.");
			}
			if (key.Length != KeyLen)
			{
				throw new ArgumentException($"Key length must be {KeyLen} bytes.", nameof(key));
			}
			LibraryInitializer.EnsureInitialized();
			if (Native.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key) != 0)
			{
				throw new LibSodiumException("Failed to initialize decryption. Ensure the header and key are correct.");
			}
		}

		/// <summary>
		/// Initializes the authenticated decryption process for a secret stream.
		/// </summary>
		/// <param name="state">The span to write the initial state to. Must be <see cref="StateLen"/> bytes long.</param>
		/// <param name="header">The stream header received from the sender. Must be <see cref="HeaderLen"/> bytes long.</param>
		/// <param name="key">The secret key used for encryption. Must be <see cref="KeyLen"/> bytes long.</param>
		/// <exception cref="ArgumentException">If the length of the state, header, or key spans are incorrect.</exception>
		/// <exception cref="LibSodiumException">If the initialization of decryption fails, likely due to an incorrect header or key.</exception>
		public static void InitializeDecryption(SecureMemory<byte> state, ReadOnlySpan<byte> header, SecureMemory<byte> key)
		{
			InitializeDecryption(state.AsSpan(), header, key.AsReadOnlySpan());
		}


		/// <summary>
		/// Decrypts and verifies the authenticity of a block of data using the secret stream with additional authenticated data (AAD).
		/// </summary>
		/// <param name="state">The current state of the secret stream. Must be <see cref="StateLen"/> bytes long.</param>
		/// <param name="cleartext">The span to write the decrypted data to. Must have a length of at least <paramref name="ciphertext"/>.<see cref="Span{T}.Length"/> - <see cref="OverheadLen"/>.</param>
		/// <param name="tag">When this method returns, contains the tag associated with the decrypted message.</param>
		/// <param name="ciphertext">The encrypted and authenticated data to decrypt.</param>
		/// <param name="additionalData">Additional authenticated data that was cryptographically incorporated during the calculation of the authentication tag for the corresponding ciphertext. This value **must be identical** to the one used during the <see cref="EncryptChunk(Span{byte}, Span{byte}, ReadOnlySpan{byte}, CryptoSecretStreamTag, ReadOnlySpan{byte})"/> call for authentication to succeed.</param>
		/// <returns>A <see cref="Span{T}"/> representing the decrypted data written to <paramref name="cleartext"/>.</returns>
		/// <exception cref="ArgumentException">If the length of the state or cleartext spans are incorrect.</exception>
		/// <exception cref="LibSodiumException">If the decryption or authentication of the chunk fails, likely due to tampered ciphertext or incorrect AAD.</exception>
		public static Span<byte> DecryptChunk(
			Span<byte> state,
			Span<byte> cleartext,
			out CryptoSecretStreamTag tag,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> additionalData = default
			)
		{
			if (state.Length != StateLen)
			{
				throw new ArgumentException($"State length must be {StateLen} bytes.", nameof(state));
			}
			if (cleartext.Length < ciphertext.Length - OverheadLen)
			{
				throw new ArgumentException($"Cleartext length must be at least {ciphertext.Length - OverheadLen} bytes.", nameof(cleartext));
			}
			LibraryInitializer.EnsureInitialized();
			byte tagByte;
			if (Native.crypto_secretstream_xchacha20poly1305_pull(state, cleartext, out var cleartextLen, out tagByte, ciphertext, (ulong)ciphertext.Length, additionalData, (ulong)additionalData.Length) != 0)
			{
				throw new LibSodiumException("Failed to decrypt and authenticate chunk. The ciphertext or additional data may have been tampered with");
			}
			tag = (CryptoSecretStreamTag)tagByte;
			return cleartext.Slice(0, (int)cleartextLen);
		}

		/// <summary>
		/// Decrypts and verifies the authenticity of a block of data using the secret stream with additional authenticated data (AAD).
		/// </summary>
		/// <param name="state">The current state of the secret stream. Must be <see cref="StateLen"/> bytes long.</param>
		/// <param name="cleartext">The span to write the decrypted data to. Must have a length of at least <paramref name="ciphertext"/>.<see cref="Span{T}.Length"/> - <see cref="OverheadLen"/>.</param>
		/// <param name="tag">When this method returns, contains the tag associated with the decrypted message.</param>
		/// <param name="ciphertext">The encrypted and authenticated data to decrypt.</param>
		/// <param name="additionalData">Additional authenticated data that was cryptographically incorporated during the calculation of the authentication tag for the corresponding ciphertext. This value **must be identical** to the one used during the <see cref="EncryptChunk(Span{byte}, Span{byte}, ReadOnlySpan{byte}, CryptoSecretStreamTag, ReadOnlySpan{byte})"/> call for authentication to succeed.</param>
		/// <returns>A <see cref="Span{T}"/> representing the decrypted data written to <paramref name="cleartext"/>.</returns>
		/// <exception cref="ArgumentException">If the length of the state or cleartext spans are incorrect.</exception>
		/// <exception cref="LibSodiumException">If the decryption or authentication of the chunk fails, likely due to tampered ciphertext or incorrect AAD.</exception>
		public static Span<byte> DecryptChunk(
			SecureMemory<byte> state,
			Span<byte> cleartext,
			out CryptoSecretStreamTag tag,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> additionalData = default
			)
		{
			return DecryptChunk(state.AsSpan(), cleartext, out tag, ciphertext, additionalData);
		}
	}
}