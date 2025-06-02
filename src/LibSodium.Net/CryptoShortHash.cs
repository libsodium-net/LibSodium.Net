

using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides a high-level interface to the libsodium short-input hash function, based on SipHash-2-4.
	/// </summary>
	/// <remarks>
	/// This function is optimized for short messages and uses a 16-byte secret key to protect against hash-flooding
	/// attacks. It is not suitable for general-purpose cryptographic hashing.
	/// <para>
	/// 🧂 https://libsodium.gitbook.io/doc/hashing/short-input_hashing
	/// </para>
	/// </remarks>
	public static class CryptoShortHash
    {
        /// <summary>
        /// Hash length in bytes (8).
        /// </summary>
        public const int HashLen = Native.CRYPTO_SHORTHASH_BYTES;

        /// <summary>
        /// Key length in bytes (16).
        /// </summary>
        public const int KeyLen = Native.CRYPTO_SHORTHASH_KEYBYTES;

		/// <summary>
		/// Computes a short hash (SipHash-2-4) of the given message using the provided 16-byte key. The key must remain secret. 
		/// This function will not provide any mitigations against DoS attacks if the key is known from attackers.
		/// </summary>
		/// <param name="hash">A buffer of exactly 8 bytes to receive the output.</param>
		/// <param name="message">The message to hash.</param>
		/// <param name="key">A 16-byte secret key.</param>
		/// <exception cref="ArgumentException">Thrown if the key or hash buffer is not of expected length.</exception>
		/// <exception cref="LibSodiumException">Thrown if the hashing operation fails.</exception>
		public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
        {
            if (hash.Length != HashLen)
                throw new ArgumentException($"Hash length must be exactly {HashLen} bytes.", nameof(hash));
            if (key.Length != KeyLen)
                throw new ArgumentException($"Key length must be exactly {KeyLen} bytes.", nameof(key));

            LibraryInitializer.EnsureInitialized();

            int result = Native.crypto_shorthash(hash, message, (ulong)message.Length, key);
            if (result != 0)
                throw new LibSodiumException("Short hash computation failed.");
        }

		/// <summary>
		/// Computes a short hash (SipHash-2-4) of the given message using the provided 16-byte key. The key must remain secret. 
		/// This function will not provide any mitigations against DoS attacks if the key is known from attackers.
		/// </summary>
		/// <param name="hash">A buffer of exactly 8 bytes to receive the output.</param>
		/// <param name="message">The message to hash.</param>
		/// <param name="key">A 16-byte secret key.</param>
		/// <exception cref="ArgumentException">Thrown if the key or hash buffer is not of expected length.</exception>
		/// <exception cref="LibSodiumException">Thrown if the hashing operation fails.</exception>
		public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message, SecureMemory<byte> key)
		{
			ComputeHash(hash, message, key.AsReadOnlySpan());
		}
	}
}
