namespace LibSodium
{
	/// <summary>
	/// Provides high-level access to the Curve25519-based public-key authenticated encryption (crypto_box) from Libsodium.
	/// </summary>
	/// <remarks>
	/// This class supports both combined and detached modes, auto nonce, as well as encryption using precomputed shared keys.
	/// </remarks>
	public static class CryptoBox
	{
		/// <summary>
		/// Public key length in bytes (32).
		/// </summary>
		public static int PublicKeyLen => LowLevel.CryptoBox.PublicKeyLen;
		/// <summary>
		/// Private key length in bytes (32).
		/// </summary>
		public static int PrivateKeyLen => LowLevel.CryptoBox.PrivateKeyLen;
		/// <summary>
		/// Shared key length in bytes (32).
		/// </summary>
		public static int SharedKeyLen => LowLevel.CryptoBox.SharedKeyLen;
		/// <summary>
		/// Nonce length in bytes (24).
		/// </summary>
		public static int NonceLen => LowLevel.CryptoBox.NonceLen;
		/// <summary>
		/// MAC length in bytes (16).
		/// </summary>
		public static int MacLen => LowLevel.CryptoBox.MacLen;
		/// <summary>
		/// Seed length in bytes (32).
		/// </summary>
		public static int SeedLen => LowLevel.CryptoBox.SeedLen;

		/// <summary>
		/// Length of the ciphertext overhead (48) when using EncryptWithPublicKey and DecryptWithPrivateKey.
		/// </summary>
		public static int SealOverheadLen => PublicKeyLen + MacLen;

		/// <summary>
		/// Generates a new Curve25519 key pair for use with crypto_box.
		/// </summary>
		/// <param name="publicKey">The buffer where the generated public key (32 bytes) will be written.</param>
		/// <param name="privateKey">The buffer where the generated private key (32 bytes) will be written.</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if key generation fails.</exception>
		public static void GenerateKeypair(Span<byte> publicKey, Span<byte> privateKey)
		{
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(publicKey));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes long.", nameof(privateKey));
			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.GenerateKeypair(publicKey, privateKey) != 0)
			{
				throw new LibSodiumException("Failed to generate keypair.");
			}
		}

		/// <summary>
		/// Generates a new Curve25519 key pair for use with crypto_box.
		/// </summary>
		/// <param name="publicKey">The buffer where the generated public key (32 bytes) will be written.</param>
		/// <param name="privateKey">The buffer where the generated private key (32 bytes) will be written.</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if key generation fails.</exception>
		public static void GenerateKeypair(Span<byte> publicKey, SecureMemory<byte> privateKey)
		{
			GenerateKeypair(publicKey, privateKey.AsSpan());
		}

		/// <summary>
		/// Generates a Curve25519 key pair deterministically from a seed.
		/// </summary>
		/// <param name="publicKey">The buffer where the generated public key (32 bytes) will be written.</param>
		/// <param name="privateKey">The buffer where the generated private key (32 bytes) will be written.</param>
		/// <param name="seed">The seed to use for deterministic key generation (32 bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if key generation fails.</exception>
		public static void GenerateKeypairDeterministically(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed)
		{
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(publicKey));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes long.", nameof(privateKey));
			if (seed.Length != SeedLen)
				throw new ArgumentException($"Seed must be {SeedLen} bytes long.", nameof(seed));
			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.GenerateKeypairDeterministically(publicKey, privateKey, seed) != 0)
			{
				throw new LibSodiumException("Failed to generate keypair.");
			}
		}

		/// <summary>
		/// Generates a Curve25519 key pair deterministically from a seed.
		/// </summary>
		/// <param name="publicKey">The buffer where the generated public key (32 bytes) will be written.</param>
		/// <param name="privateKey">The buffer where the generated private key (32 bytes) will be written.</param>
		/// <param name="seed">The seed to use for deterministic key generation (32 bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if key generation fails.</exception>
		public static void GenerateKeypairDeterministically(Span<byte> publicKey, SecureMemory<byte> privateKey, ReadOnlySpan<byte> seed)
		{
			GenerateKeypairDeterministically(publicKey, privateKey.AsSpan(), seed);
		}

		/// <summary>
		/// Calculates the Curve25519 public key from a given private key.
		/// </summary>
		/// <param name="publicKey">The buffer where the calculated public key (32 bytes) will be written.</param>
		/// <param name="privateKey">The private key to derive from (32 bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if public key calculation fails.</exception>
		public static void CalculatePublicKey(Span<byte> publicKey, ReadOnlySpan<byte> privateKey)
		{
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(publicKey));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes long.", nameof(privateKey));
			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.CalculatePublicKey(publicKey, privateKey) != 0)
			{
				throw new LibSodiumException("Failed to calculate public key.");
			}
		}

		/// <summary>
		/// Calculates the Curve25519 public key from a given private key.
		/// </summary>
		/// <param name="publicKey">The buffer where the calculated public key (32 bytes) will be written.</param>
		/// <param name="privateKey">The private key to derive from (32 bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if public key calculation fails.</exception>
		public static void CalculatePublicKey(Span<byte> publicKey, SecureMemory<byte> privateKey)
		{
			CalculatePublicKey(publicKey, privateKey.AsReadOnlySpan());
		}

		/// <summary>
		/// Calculates a shared secret using a peer's public key and the local private key.
		/// </summary>
		/// <param name="sharedKey">The buffer where the shared key (32 bytes) will be written.</param>
		/// <param name="peerPublicKey">The peer's public key (32 bytes).</param>
		/// <param name="localPrivateKey">The local private key (32 bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if shared key calculation fails.</exception>
		public static void CalculateSharedKey(Span<byte> sharedKey, ReadOnlySpan<byte> peerPublicKey, ReadOnlySpan<byte> localPrivateKey)
		{
			if (sharedKey.Length != SharedKeyLen)
				throw new ArgumentException($"Shared key must be {SharedKeyLen} bytes long.", nameof(sharedKey));
			if (peerPublicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(peerPublicKey));
			if (localPrivateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes long.", nameof(localPrivateKey));
			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.CalculateSharedKey(sharedKey, peerPublicKey, localPrivateKey) != 0)
			{
				throw new LibSodiumException("Failed to calculate shared key.");
			}
		}

		/// <summary>
		/// Calculates a shared secret using a peer's public key and the local private key.
		/// </summary>
		/// <param name="sharedKey">The buffer where the shared key (32 bytes) will be written.</param>
		/// <param name="peerPublicKey">The peer's public key (32 bytes).</param>
		/// <param name="localPrivateKey">The local private key (32 bytes).</param>
		/// <exception cref="ArgumentException">Thrown if the buffer sizes are incorrect.</exception>
		/// <exception cref="LibSodiumException">Thrown if shared key calculation fails.</exception>
		public static void CalculateSharedKey(SecureMemory<byte> sharedKey, ReadOnlySpan<byte> peerPublicKey, SecureMemory<byte> localPrivateKey)
		{
			CalculateSharedKey(sharedKey.AsSpan(), peerPublicKey, localPrivateKey.AsReadOnlySpan());
		}


		internal static Span<byte> EncryptCombined(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> nonce)
		{
			if (ciphertext.Length < plaintext.Length + MacLen)
				throw new ArgumentException($"Ciphertext must be at least {plaintext.Length + MacLen} bytes long.", nameof(ciphertext));
			if (nonce.Length != NonceLen)
				throw new ArgumentException($"Nonce must be {NonceLen} bytes long.", nameof(nonce));
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(publicKey));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes long.", nameof(privateKey));
			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.EncryptCombined(ciphertext, plaintext, nonce, publicKey, privateKey) != 0)
			{
				throw new LibSodiumException("Failed to encrypt.");
			}
			return ciphertext.Slice(0, plaintext.Length + MacLen);
		}

		internal static Span<byte> EncryptCombined(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
		{
			if (ciphertext.Length < plaintext.Length + MacLen + NonceLen)
				throw new ArgumentException($"Ciphertext must be at least {plaintext.Length + MacLen + NonceLen} bytes long.", nameof(ciphertext));

			var nonce = ciphertext.Slice(0, NonceLen);
			RandomGenerator.Fill(nonce);
			var ciphertextSlice = ciphertext.Slice(NonceLen);
			EncryptCombined(ciphertextSlice, plaintext, publicKey, privateKey, nonce);
			return ciphertext.Slice(0, plaintext.Length + MacLen + NonceLen);
		}

		internal static Span<byte> DecryptCombined(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> nonce)
		{
			if (ciphertext.Length < MacLen)
				throw new ArgumentException($"Ciphertext must be at least {MacLen} bytes long.", nameof(ciphertext));
			if (plaintext.Length < ciphertext.Length - MacLen)
				throw new ArgumentException($"Plaintext must be at least {ciphertext.Length - MacLen} bytes long.", nameof(plaintext));
			if (nonce.Length != NonceLen)
				throw new ArgumentException($"Nonce must be {NonceLen} bytes long.", nameof(nonce));
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(publicKey));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes long.", nameof(privateKey));
			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.DecryptCombined(plaintext, ciphertext, nonce, publicKey, privateKey) != 0)
			{
				throw new LibSodiumException("Failed to decrypt.");
			}
			return plaintext.Slice(0, ciphertext.Length - MacLen);
		}

		internal static Span<byte> DecryptCombined(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
		{
			if (ciphertext.Length < MacLen + NonceLen)
				throw new ArgumentException($"Ciphertext must be at least {MacLen + NonceLen} bytes long.", nameof(ciphertext));
			if (plaintext.Length < ciphertext.Length - MacLen - NonceLen)
				throw new ArgumentException($"Plaintext must be at least {ciphertext.Length - MacLen - NonceLen} bytes long.", nameof(plaintext));
			var nonce = ciphertext.Slice(0, NonceLen);
			var ciphertextSlice = ciphertext.Slice(NonceLen);
			return DecryptCombined(plaintext, ciphertextSlice, publicKey, privateKey, nonce);
		}

		internal static Span<byte> EncryptDetached(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey, Span<byte> mac, ReadOnlySpan<byte> nonce)
		{
			if (ciphertext.Length < plaintext.Length)
				throw new ArgumentException($"Ciphertext must be at least {plaintext.Length} bytes long.", nameof(ciphertext));
			if (mac.Length != MacLen)
				throw new ArgumentException($"MAC must be {MacLen} bytes long.", nameof(mac));
			if (nonce.Length != NonceLen)
				throw new ArgumentException($"Nonce must be {NonceLen} bytes long.", nameof(nonce));
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(publicKey));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes long.", nameof(privateKey));
			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.EncryptDetached(ciphertext, mac, plaintext, nonce, publicKey, privateKey) != 0)
			{
				throw new LibSodiumException("Failed to encrypt.");
			}
			return ciphertext.Slice(0, plaintext.Length);
		}

		internal static Span<byte> EncryptDetached(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey, Span<byte> mac)
		{
			if (ciphertext.Length < plaintext.Length + NonceLen)
				throw new ArgumentException($"Ciphertext must be at least {plaintext.Length + NonceLen} bytes long.", nameof(ciphertext));
			var nonce = ciphertext.Slice(0, NonceLen);
			RandomGenerator.Fill(nonce);
			var ciphertextSlice = ciphertext.Slice(NonceLen);
			EncryptDetached(ciphertextSlice, plaintext, publicKey, privateKey, mac, nonce);
			return ciphertext.Slice(0, plaintext.Length + NonceLen);
		}

		internal static Span<byte> DecryptDetached(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> nonce)
		{
			if (plaintext.Length < ciphertext.Length)
				throw new ArgumentException($"Plaintext must be at least {ciphertext.Length} bytes long.", nameof(plaintext));
			if (mac.Length != MacLen)
				throw new ArgumentException($"MAC must be {MacLen} bytes long.", nameof(mac));
			if (nonce.Length != NonceLen)
				throw new ArgumentException($"Nonce must be {NonceLen} bytes long.", nameof(nonce));
			if (publicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Public key must be {PublicKeyLen} bytes long.", nameof(publicKey));
			if (privateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Private key must be {PrivateKeyLen} bytes long.", nameof(privateKey));
			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.DecryptDetached(plaintext, ciphertext, mac, nonce, publicKey, privateKey) != 0)
			{
				throw new LibSodiumException("Failed to decrypt.");
			}
			return plaintext.Slice(0, ciphertext.Length);
		}

		internal static Span<byte> DecryptDetached(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> mac)
		{
			if (ciphertext.Length < NonceLen)
				throw new ArgumentException($"Ciphertext must be at least {NonceLen} bytes long.", nameof(ciphertext));
			if (plaintext.Length < ciphertext.Length - NonceLen)
				throw new ArgumentException($"Plaintext must be at least {ciphertext.Length + NonceLen} bytes long.", nameof(plaintext));
			var nonce = ciphertext.Slice(0, NonceLen);
			var ciphertextSlice = ciphertext.Slice(NonceLen);
			return DecryptDetached(plaintext, ciphertextSlice, publicKey, privateKey, mac, nonce);
		}

		/// <summary>
		/// Encrypts a message using the recipient's public key and the sender's private key.
		/// Supports both combined and detached modes, with optional nonce.
		/// </summary>
		/// <param name="ciphertext">
		/// The buffer where the ciphertext will be written. 
		/// Must be large enough to hold the output (plaintext + 16 bytes MAC [+ 24 bytes nonce if auto-generated]).
		/// </param>
		/// <param name="plaintext">The message to encrypt.</param>
		/// <param name="recipientPublicKey">The recipient's public key (32 bytes).</param>
		/// <param name="senderPrivateKey">The sender's private key (32 bytes).</param>
		/// <param name="mac">
		/// Optional. If provided, encryption is done in detached mode and the MAC (16 bytes) is written here.
		/// Otherwise, combined mode is used.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided, a random nonce is generated and prepended.
		/// </param>
		/// <returns>The span representing the full ciphertext, including MAC and possibly nonce.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when encryption fails.</exception>
		public static Span<byte> EncryptWithKeypair(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> senderPrivateKey, Span<byte> mac = default, ReadOnlySpan<byte> nonce = default)
		{
			if (mac == default)
			{
				if (nonce == default)
				{
					return EncryptCombined(ciphertext, plaintext, recipientPublicKey, senderPrivateKey);
				}
				return EncryptCombined(ciphertext, plaintext, recipientPublicKey, senderPrivateKey, nonce);
			}
			else
			{
				if (nonce == default)
				{
					return EncryptDetached(ciphertext, plaintext, recipientPublicKey, senderPrivateKey, mac);
				}
				return EncryptDetached(ciphertext, plaintext, recipientPublicKey, senderPrivateKey, mac, nonce);
			}
		}

		/// <summary>
		/// Encrypts a message using the recipient's public key and the sender's private key.
		/// Supports both combined and detached modes, with optional nonce.
		/// </summary>
		/// <param name="ciphertext">
		/// The buffer where the ciphertext will be written. 
		/// Must be large enough to hold the output (plaintext + 16 bytes MAC [+ 24 bytes nonce if auto-generated]).
		/// </param>
		/// <param name="plaintext">The message to encrypt.</param>
		/// <param name="recipientPublicKey">The recipient's public key (32 bytes).</param>
		/// <param name="senderPrivateKey">The sender's private key (32 bytes).</param>
		/// <param name="mac">
		/// Optional. If provided, encryption is done in detached mode and the MAC (16 bytes) is written here.
		/// Otherwise, combined mode is used.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided, a random nonce is generated and prepended.
		/// </param>
		/// <returns>The span representing the full ciphertext, including MAC and possibly nonce.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when encryption fails.</exception>
		public static Span<byte> EncryptWithKeypair(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> recipientPublicKey, SecureMemory<byte> senderPrivateKey, Span<byte> mac = default, ReadOnlySpan<byte> nonce = default)
		{
			return EncryptWithKeypair(ciphertext, plaintext, recipientPublicKey, senderPrivateKey.AsReadOnlySpan(), mac, nonce);
		}

		/// <summary>
		/// Decrypts a message using the recipient's private key and the sender's public key.
		/// Supports both combined and detached modes, with optional nonce.
		/// </summary>
		/// <param name="plaintext">The buffer where the decrypted message will be written.</param>
		/// <param name="ciphertext">
		/// The encrypted message. May include MAC and nonce (combined) or exclude them (detached).
		/// </param>
		/// <param name="senderPublicKey">The sender's public key (32 bytes).</param>
		/// <param name="recipientPrivateKey">The recipient's private key (32 bytes).</param>
		/// <param name="mac">
		/// Optional. If provided, decryption is done in detached mode. Otherwise, combined mode is used.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided it is taken from the beginning of the ciphertext.
		/// </param>
		/// <returns>The span representing the decrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when MAC verification fails or decryption fails.</exception>
		public static Span<byte> DecryptWithKeypair(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> senderPublicKey, ReadOnlySpan<byte> recipientPrivateKey, ReadOnlySpan<byte> mac = default, ReadOnlySpan<byte> nonce = default)
		{
			if (mac == default)
			{
				if (nonce == default)
				{
					return DecryptCombined(plaintext, ciphertext, senderPublicKey, recipientPrivateKey);
				}
				return DecryptCombined(plaintext, ciphertext, senderPublicKey, recipientPrivateKey, nonce);
			}
			else
			{
				if (nonce == default)
				{
					return DecryptDetached(plaintext, ciphertext, senderPublicKey, recipientPrivateKey, mac);
				}
				return DecryptDetached(plaintext, ciphertext, senderPublicKey, recipientPrivateKey, mac, nonce);
			}
		}

		/// <summary>
		/// Decrypts a message using the recipient's private key and the sender's public key.
		/// Supports both combined and detached modes, with optional nonce.
		/// </summary>
		/// <param name="plaintext">The buffer where the decrypted message will be written.</param>
		/// <param name="ciphertext">
		/// The encrypted message. May include MAC and nonce (combined) or exclude them (detached).
		/// </param>
		/// <param name="senderPublicKey">The sender's public key (32 bytes).</param>
		/// <param name="recipientPrivateKey">The recipient's private key (32 bytes).</param>
		/// <param name="mac">
		/// Optional. If provided, decryption is done in detached mode. Otherwise, combined mode is used.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided it is taken from the beginning of the ciphertext.
		/// </param>
		/// <returns>The span representing the decrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when MAC verification fails or decryption fails.</exception>
		public static Span<byte> DecryptWithKeypair(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> senderPublicKey, SecureMemory<byte> recipientPrivateKey, ReadOnlySpan<byte> mac = default, ReadOnlySpan<byte> nonce = default)
		{
			return DecryptWithKeypair(plaintext, ciphertext, senderPublicKey, recipientPrivateKey.AsReadOnlySpan(), mac, nonce);
		}

		internal static Span<byte> EncryptCombinedWithSharedKey(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> nonce)
		{
			if (sharedKey.Length != SharedKeyLen)
				throw new ArgumentException($"Shared key must be {SharedKeyLen} bytes.", nameof(sharedKey));
			if (nonce.Length != NonceLen)
				throw new ArgumentException($"Nonce must be {NonceLen} bytes.", nameof(nonce));
			if (ciphertext.Length < plaintext.Length + MacLen)
				throw new ArgumentException("Ciphertext buffer too small.", nameof(ciphertext));
			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.EncryptCombinedWithSharedKey(ciphertext, plaintext, nonce, sharedKey) != 0)
				throw new LibSodiumException("Encryption failed.");

			return ciphertext.Slice(0, plaintext.Length + MacLen);
		}

		internal static Span<byte> EncryptCombinedWithSharedKey(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> sharedKey)
		{
			if (sharedKey.Length != SharedKeyLen)
				throw new ArgumentException($"Shared key must be {SharedKeyLen} bytes.", nameof(sharedKey));
			if (ciphertext.Length < plaintext.Length + MacLen + NonceLen)
				throw new ArgumentException("Ciphertext buffer too small.", nameof(ciphertext));

			var nonce = ciphertext.Slice(0, NonceLen);
			RandomGenerator.Fill(nonce);
			var content = ciphertext.Slice(NonceLen);
			EncryptCombinedWithSharedKey(content, plaintext, sharedKey, nonce);
			return ciphertext.Slice(0, plaintext.Length + MacLen + NonceLen);
		}

		internal static Span<byte> DecryptCombinedWithSharedKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> nonce)
		{
			if (sharedKey.Length != SharedKeyLen)
				throw new ArgumentException($"Shared key must be {SharedKeyLen} bytes.", nameof(sharedKey));
			if (nonce.Length != NonceLen)
				throw new ArgumentException($"Nonce must be {NonceLen} bytes.", nameof(nonce));
			if (ciphertext.Length < MacLen)
				throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));

			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.DecryptCombinedWithSharedKey(plaintext, ciphertext, nonce, sharedKey) != 0)
				throw new LibSodiumException("Decryption failed.");

			return plaintext.Slice(0, ciphertext.Length - MacLen);
		}

		internal static Span<byte> DecryptCombinedWithSharedKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> sharedKey)
		{
			if (sharedKey.Length != SharedKeyLen)
				throw new ArgumentException($"Shared key must be {SharedKeyLen} bytes.", nameof(sharedKey));
			if (ciphertext.Length < NonceLen + MacLen)
				throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));

			var nonce = ciphertext.Slice(0, NonceLen);
			var content = ciphertext.Slice(NonceLen);
			return DecryptCombinedWithSharedKey(plaintext, content, sharedKey, nonce);
		}

		internal static Span<byte> EncryptDetachedWithSharedKey(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> sharedKey, Span<byte> mac, ReadOnlySpan<byte> nonce)
		{
			if (sharedKey.Length != SharedKeyLen)
				throw new ArgumentException($"Shared key must be {SharedKeyLen} bytes.", nameof(sharedKey));
			if (nonce.Length != NonceLen)
				throw new ArgumentException($"Nonce must be {NonceLen} bytes.", nameof(nonce));
			if (mac.Length != MacLen)
				throw new ArgumentException($"MAC must be {MacLen} bytes.", nameof(mac));
			if (ciphertext.Length < plaintext.Length)
				throw new ArgumentException("Ciphertext buffer too small.", nameof(ciphertext));

			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.EncryptDetachedWithSharedKey(ciphertext, mac, plaintext, nonce, sharedKey) != 0)
				throw new LibSodiumException("Encryption failed.");

			return ciphertext.Slice(0, plaintext.Length);
		}

		internal static Span<byte> EncryptDetachedWithSharedKey(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> sharedKey, Span<byte> mac)
		{
			if (sharedKey.Length != SharedKeyLen)
				throw new ArgumentException($"Shared key must be {SharedKeyLen} bytes.", nameof(sharedKey));
			if (ciphertext.Length < plaintext.Length + NonceLen)
				throw new ArgumentException("Ciphertext buffer too small.", nameof(ciphertext));

			var nonce = ciphertext.Slice(0, NonceLen);
			RandomGenerator.Fill(nonce);
			var content = ciphertext.Slice(NonceLen);
			EncryptDetachedWithSharedKey(content, plaintext, sharedKey, mac, nonce);
			return ciphertext.Slice(0, plaintext.Length + NonceLen);
		}

		internal static Span<byte> DecryptDetachedWithSharedKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> mac, ReadOnlySpan<byte> nonce)
		{
			if (sharedKey.Length != SharedKeyLen)
				throw new ArgumentException($"Shared key must be {SharedKeyLen} bytes.", nameof(sharedKey));
			if (nonce.Length != NonceLen)
				throw new ArgumentException($"Nonce must be {NonceLen} bytes.", nameof(nonce));
			if (mac.Length != MacLen)
				throw new ArgumentException($"MAC must be {MacLen} bytes.", nameof(mac));
			if (plaintext.Length < ciphertext.Length)
				throw new ArgumentException("Plaintext buffer too small.", nameof(plaintext));

			if (LowLevel.CryptoBox.DecryptDetachedWithSharedKey(plaintext, ciphertext, mac, nonce, sharedKey) != 0)
				throw new LibSodiumException("Decryption failed.");

			return plaintext.Slice(0, ciphertext.Length);
		}

		internal static Span<byte> DecryptDetachedWithSharedKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> mac)
		{
			if (ciphertext.Length < NonceLen)
				throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));
			if (plaintext.Length < ciphertext.Length - NonceLen)
				throw new ArgumentException($"Plaintext must be at least {ciphertext.Length - NonceLen} bytes long.", nameof(plaintext));
			if (sharedKey.Length != SharedKeyLen)
				throw new ArgumentException($"Shared key must be {SharedKeyLen} bytes.", nameof(sharedKey));
			if (ciphertext.Length < NonceLen)
				throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));

			var nonce = ciphertext.Slice(0, NonceLen);
			var content = ciphertext.Slice(NonceLen);
			return DecryptDetachedWithSharedKey(plaintext, content, sharedKey, mac, nonce);
		}

		/// <summary>
		/// Encrypts a message using a precomputed shared key.
		/// Supports both combined and detached modes, with optional nonce.
		/// </summary>
		/// <param name="ciphertext">
		/// The buffer where the ciphertext will be written. 
		/// Must be large enough to hold the output (plaintext + 16 bytes MAC [+ 24 bytes nonce if auto-generated]).
		/// </param>
		/// <param name="plaintext">The message to encrypt.</param>
		/// <param name="sharedKey">The shared key (32 bytes) previously computed using <c>CalculateSharedKey</c>.</param>
		/// <param name="mac">
		/// Optional. If provided, encryption is done in detached mode and the MAC (16 bytes) is written here.
		/// Otherwise, combined mode is used.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided, a random nonce is generated and prepended.
		/// </param>
		/// <returns>The span representing the full ciphertext, including MAC and possibly nonce.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when encryption fails.</exception>
		public static Span<byte> EncryptWithSharedKey(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> sharedKey, Span<byte> mac = default, ReadOnlySpan<byte> nonce = default)
		{
			if (mac == default)
			{
				if (nonce == default)
					return EncryptCombinedWithSharedKey(ciphertext, plaintext, sharedKey);
				else
					return EncryptCombinedWithSharedKey(ciphertext, plaintext, sharedKey, nonce);
			}
			else
			{
				if (nonce == default)
					return EncryptDetachedWithSharedKey(ciphertext, plaintext, sharedKey, mac);
				else
					return EncryptDetachedWithSharedKey(ciphertext, plaintext, sharedKey, mac, nonce);
			}
		}

		/// <summary>
		/// Encrypts a message using a precomputed shared key.
		/// Supports both combined and detached modes, with optional nonce.
		/// </summary>
		/// <param name="ciphertext">
		/// The buffer where the ciphertext will be written. 
		/// Must be large enough to hold the output (plaintext + 16 bytes MAC [+ 24 bytes nonce if auto-generated]).
		/// </param>
		/// <param name="plaintext">The message to encrypt.</param>
		/// <param name="sharedKey">The shared key (32 bytes) previously computed using <c>CalculateSharedKey</c>.</param>
		/// <param name="mac">
		/// Optional. If provided, encryption is done in detached mode and the MAC (16 bytes) is written here.
		/// Otherwise, combined mode is used.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided, a random nonce is generated and prepended.
		/// </param>
		/// <returns>The span representing the full ciphertext, including MAC and possibly nonce.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when encryption fails.</exception>
		public static Span<byte> EncryptWithSharedKey(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, SecureMemory<byte> sharedKey, Span<byte> mac = default, ReadOnlySpan<byte> nonce = default)
		{
			return EncryptWithSharedKey(ciphertext, plaintext, sharedKey.AsReadOnlySpan(), mac, nonce);
		}

		/// <summary>
		/// Decrypts a message using a precomputed shared key.
		/// Supports both combined and detached modes, with optional nonce.
		/// </summary>
		/// <param name="plaintext">The buffer where the decrypted message will be written.</param>
		/// <param name="ciphertext">
		/// The encrypted message. May include MAC and nonce (combined) or exclude them (detached).
		/// </param>
		/// <param name="sharedKey">The shared key (32 bytes) previously computed using <c>CalculateSharedKey</c>.</param>
		/// <param name="mac">
		/// Optional. If provided, decryption is done in detached mode. Otherwise, combined mode is used.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided, it is taken from the beginning of the ciphertext
		/// </param>
		/// <returns>The span representing the decrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when MAC verification fails or decryption fails.</exception>
		public static Span<byte> DecryptWithSharedKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> mac = default, ReadOnlySpan<byte> nonce = default)
		{
			if (mac == default)
			{
				if (nonce == default)
					return DecryptCombinedWithSharedKey(plaintext, ciphertext, sharedKey);
				else
					return DecryptCombinedWithSharedKey(plaintext, ciphertext, sharedKey, nonce);
			}
			else
			{
				if (nonce == default)
					return DecryptDetachedWithSharedKey(plaintext, ciphertext, sharedKey, mac);
				else
					return DecryptDetachedWithSharedKey(plaintext, ciphertext, sharedKey, mac, nonce);
			}
		}

		/// <summary>
		/// Decrypts a message using a precomputed shared key.
		/// Supports both combined and detached modes, with optional nonce.
		/// </summary>
		/// <param name="plaintext">The buffer where the decrypted message will be written.</param>
		/// <param name="ciphertext">
		/// The encrypted message. May include MAC and nonce (combined) or exclude them (detached).
		/// </param>
		/// <param name="sharedKey">The shared key (32 bytes) previously computed using <c>CalculateSharedKey</c>.</param>
		/// <param name="mac">
		/// Optional. If provided, decryption is done in detached mode. Otherwise, combined mode is used.
		/// </param>
		/// <param name="nonce">
		/// Optional nonce (24 bytes). If not provided, it is taken from the beginning of the ciphertext
		/// </param>
		/// <returns>The span representing the decrypted plaintext.</returns>
		/// <exception cref="ArgumentException">Thrown when buffer sizes are incorrect or parameters are invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when MAC verification fails or decryption fails.</exception>
		public static Span<byte> DecryptWithSharedKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, SecureMemory<byte> sharedKey, ReadOnlySpan<byte> mac = default, ReadOnlySpan<byte> nonce = default)
		{
			return DecryptWithSharedKey(plaintext, ciphertext, sharedKey.AsReadOnlySpan(), mac, nonce);
		}

		/// <summary>
		/// Encrypts a message anonymously using the recipient's public key.
		/// This method uses Libsodium's <c>crypto_box_seal</c> function internally,
		/// and does not require a sender key. The resulting ciphertext includes an ephemeral
		/// public key and a MAC, adding a constant overhead of <see cref="SealOverheadLen"/> bytes.
		/// </summary>
		/// <param name="ciphertext">
		/// The buffer where the sealed ciphertext will be written. 
		/// Must be at least <c>plaintext.Length + SealOverheadLen</c> bytes long.
		/// </param>
		/// <param name="plaintext">The message to encrypt.</param>
		/// <param name="recipientPublicKey">The recipient's public key (32 bytes).</param>
		/// <returns>A slice of the ciphertext buffer containing the full sealed ciphertext.</returns>
		/// <exception cref="ArgumentException">
		/// Thrown when the recipient's public key is not 32 bytes long, or when the ciphertext buffer is too small.
		/// </exception>
		/// <exception cref="LibSodiumException">
		/// Thrown when the underlying Libsodium encryption operation fails.
		/// </exception>
		public static Span<byte> EncryptWithPublicKey(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> recipientPublicKey)
		{
			if (ciphertext.Length < plaintext.Length + SealOverheadLen)
				throw new ArgumentException($"Ciphertext must be at least {plaintext.Length + SealOverheadLen} bytes long.", nameof(ciphertext));
			if (recipientPublicKey.Length != PublicKeyLen)
				throw new ArgumentException($"Recipient public key must be {PublicKeyLen} bytes long.", nameof(recipientPublicKey));

			LibraryInitializer.EnsureInitialized();
			if (LowLevel.CryptoBox.EncryptWithPublicKey(ciphertext, plaintext, recipientPublicKey) != 0)
			{
				throw new LibSodiumException("Failed to encrypt with public key.");
			}
			return ciphertext.Slice(0, plaintext.Length + SealOverheadLen);
		}



		/// <summary>
		/// Decrypts a sealed message using the recipient's private key.
		/// This method uses libsodium's <c>crypto_box_seal_open</c> internally and automatically derives the
		/// recipient's public key from the given private key. The ciphertext must have been produced
		/// using <see cref="EncryptWithPublicKey"/>.
		/// </summary>
		/// <param name="plaintext">
		/// The buffer where the decrypted message will be written.
		/// Must be at least <c>ciphertext.Length - SealOverheadLen</c> bytes long.
		/// </param>
		/// <param name="ciphertext">
		/// The sealed ciphertext, including a 32-byte ephemeral public key and a 16-byte MAC.
		/// Must be at least <see cref="SealOverheadLen"/> bytes long.
		/// </param>
		/// <param name="recipientPrivateKey">The recipient's private key (32 bytes).</param>
		/// <returns>A slice of the plaintext buffer containing the decrypted message.</returns>
		/// <exception cref="ArgumentException">
		/// Thrown when buffer sizes are invalid or the private key is not 32 bytes long.
		/// </exception>
		/// <exception cref="LibSodiumException">
		/// Thrown when the ciphertext cannot be decrypted or the MAC verification fails.
		/// </exception>

		public static Span<byte> DecryptWithPrivateKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> recipientPrivateKey)
		{
			if (ciphertext.Length < SealOverheadLen)
				throw new ArgumentException($"Ciphertext must be at least {SealOverheadLen} bytes long.", nameof(ciphertext));
			if (plaintext.Length < ciphertext.Length - SealOverheadLen) 
				throw new ArgumentException($"Plaintext must be at least {ciphertext.Length - SealOverheadLen} bytes long.", nameof(plaintext));
			if (recipientPrivateKey.Length != PrivateKeyLen)
				throw new ArgumentException($"Recipient private key must be {PrivateKeyLen} bytes long.", nameof(recipientPrivateKey));

			Span<byte> recipientPublicKey = stackalloc byte[PublicKeyLen];

			CalculatePublicKey(recipientPublicKey, recipientPrivateKey);

			if (LowLevel.CryptoBox.DecryptWithPrivateKey(plaintext, ciphertext, recipientPublicKey, recipientPrivateKey) != 0)
			{
				throw new LibSodiumException("Failed to decrypt with private key.");
			}
			return plaintext.Slice(0, ciphertext.Length - SealOverheadLen);
		}

		/// <summary>
		/// Decrypts a sealed message using the recipient's private key.
		/// This method uses libsodium's <c>crypto_box_seal_open</c> internally and automatically derives the
		/// recipient's public key from the given private key. The ciphertext must have been produced
		/// using <see cref="EncryptWithPublicKey"/>.
		/// </summary>
		/// <param name="plaintext">
		/// The buffer where the decrypted message will be written.
		/// Must be at least <c>ciphertext.Length - SealOverheadLen</c> bytes long.
		/// </param>
		/// <param name="ciphertext">
		/// The sealed ciphertext, including a 32-byte ephemeral public key and a 16-byte MAC.
		/// Must be at least <see cref="SealOverheadLen"/> bytes long.
		/// </param>
		/// <param name="recipientPrivateKey">The recipient's private key (32 bytes).</param>
		/// <returns>A slice of the plaintext buffer containing the decrypted message.</returns>
		/// <exception cref="ArgumentException">
		/// Thrown when buffer sizes are invalid or the private key is not 32 bytes long.
		/// </exception>
		/// <exception cref="LibSodiumException">
		/// Thrown when the ciphertext cannot be decrypted or the MAC verification fails.
		/// </exception>

		public static Span<byte> DecryptWithPrivateKey(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, SecureMemory<byte> recipientPrivateKey)
		{
			return DecryptWithPrivateKey(plaintext, ciphertext, recipientPrivateKey.AsReadOnlySpan());
		}
	}
}
