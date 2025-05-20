namespace LibSodium
{
	/// <summary>
	/// Provides methods for message authentication using the crypto_auth API from libsodium.
	/// </summary>
	/// <remarks>
	/// This class wraps the <c>crypto_auth</c> functions from <a href="https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication">libsodium's secret-key authentication API</a>,
	/// which uses the HMAC-SHA-512-256 algorithm to generate and verify message authentication codes (MACs).
	/// </remarks>
	[Obsolete("Use CryptoHmacSha512_256 instead. CryptoAuth is deprecated and will be removed in future versions.")]
	public static class CryptoAuth
	{
		/// <summary>
		/// The length, in bytes, of a valid secret key for HMAC-SHA-512-256.
		/// </summary>
		public const int KeyLen = Interop.Native.CRYPTO_AUTH_KEYBYTES;

		/// <summary>
		/// The length, in bytes, of the MAC produced by HMAC-SHA-512-256.
		/// </summary>
		public const int MacLen = Interop.Native.CRYPTO_AUTH_BYTES;

		/// <summary>
		/// Generates a new random secret key for use with HMAC-SHA-512-256.
		/// </summary>
		/// <param name="key">A writable buffer with a length of <see cref="KeyLen"/> bytes that will be filled with the generated key.</param>
		/// <exception cref="ArgumentException">Thrown when the buffer length is not equal to <see cref="KeyLen"/>.</exception>
		/// <remarks>
		/// This function uses a cryptographically secure random number generator to produce a secret key.
		/// Internally calls <c>crypto_auth_keygen</c> from libsodium.
		/// </remarks>
		public static void GenerateKey(Span<byte> key)
		{
			if (key.Length != KeyLen)
				throw new ArgumentException($"Key length must be {KeyLen} bytes.", nameof(key));
			LibraryInitializer.EnsureInitialized();
			Interop.Native.crypto_auth_keygen(key);
		}

		/// <summary>
		/// Computes a message authentication code (MAC) for the given input using HMAC-SHA-512-256.
		/// </summary>
		/// <param name="mac">A writable buffer with a length of <see cref="MacLen"/> bytes that will receive the computed MAC.</param>
		/// <param name="input">The message data to authenticate.</param>
		/// <param name="key">The secret key to use for authentication, must be <see cref="KeyLen"/> bytes long.</param>
		/// <exception cref="ArgumentException">Thrown when the length of <paramref name="mac"/> or <paramref name="key"/> is invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when the underlying libsodium operation fails unexpectedly.</exception>
		/// <remarks>
		/// This method is a wrapper around libsodium's <c>crypto_auth</c> function.
		/// </remarks>
		public static void ComputeMac(Span<byte> mac, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key)
		{
			if (mac.Length != MacLen)
				throw new ArgumentException($"MAC length must be {MacLen} bytes.", nameof(mac));
			if (key.Length != KeyLen)
				throw new ArgumentException($"Key length must be {KeyLen} bytes.", nameof(key));
			LibraryInitializer.EnsureInitialized();
			if (Interop.Native.crypto_auth(mac, input, (ulong)input.Length, key) != 0)
			{
				throw new LibSodiumException("Failed to compute MAC.");
			};
		}

		/// <summary>
		/// Attempts to verify that a given MAC is valid for the specified input and key using HMAC-SHA-512-256.
		/// </summary>
		/// <param name="mac">The message authentication code to verify. Must be <see cref="MacLen"/> bytes long.</param>
		/// <param name="input">The original message data that the MAC should authenticate.</param>
		/// <param name="key">The secret key that was used to generate the MAC. Must be <see cref="KeyLen"/> bytes long.</param>
		/// <returns><c>true</c> if the MAC is valid; otherwise, <c>false</c>.</returns>
		/// <exception cref="ArgumentException">Thrown when the length of <paramref name="mac"/> or <paramref name="key"/> is invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when an unexpected error occurs during verification.</exception>
		/// <remarks>
		/// This method wraps the <c>crypto_auth_verify</c> function from libsodium.
		/// </remarks>
		public static bool TryVerifyMac(ReadOnlySpan<byte> mac, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key)
		{
			if (mac.Length != MacLen)
				throw new ArgumentException($"MAC length must be {MacLen} bytes.", nameof(mac));
			if (key.Length != KeyLen)
				throw new ArgumentException($"Key length must be {KeyLen} bytes.", nameof(key));
			LibraryInitializer.EnsureInitialized();
			var result = Interop.Native.crypto_auth_verify(mac, input, (ulong)input.Length, key);
			if (result == 0) return true;
			if (result == -1) return false;
			throw new LibSodiumException("Error verifying MAC");
		}

		/// <summary>
		/// Verifies that a given MAC is valid for the specified input and key using HMAC-SHA-512-256.
		/// </summary>
		/// <param name="mac">The message authentication code to verify. Must be <see cref="MacLen"/> bytes long.</param>
		/// <param name="input">The original message data that the MAC should authenticate.</param>
		/// <param name="key">The secret key that was used to generate the MAC. Must be <see cref="KeyLen"/> bytes long.</param>
		/// <exception cref="ArgumentException">Thrown when the length of <paramref name="mac"/> or <paramref name="key"/> is invalid.</exception>
		/// <exception cref="LibSodiumException">Thrown when the MAC verification fails or an unexpected error occurs.</exception>
		/// <remarks>
		/// Internally calls <see cref="TryVerifyMac"/> and throws if the verification fails.
		/// </remarks>
		public static void VerifyMac(ReadOnlySpan<byte> mac, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key)
		{
			if (TryVerifyMac(mac, input, key))
			{
				return;
			}
			else
			{
				throw new LibSodiumException("MAC verification failed.");
			}
		}
	}
}
