using System;
using System.Text;
using LibSodium.Interop;

namespace LibSodium
{
	/// <summary>
	/// Provides deterministic key derivation using libsodium's crypto_kdf_* API,
	/// based on the BLAKE2b hash function.
	/// </summary>
	public static class CryptoKeyDerivation
	{
		/// <summary>
		/// Length of the master key in bytes (32).
		/// </summary>
		public const int MasterKeyLen = Native.CRYPTO_KDF_KEYBYTES;

		/// <summary>
		/// Minimum length of a derived subkey (16).
		/// </summary>
		public const int MinSubkeyLen = Native.CRYPTO_KDF_BYTES_MIN;

		/// <summary>
		/// Maximum length of a derived subkey (64).
		/// </summary>
		public const int MaxSubkeyLen = Native.CRYPTO_KDF_BYTES_MAX;

		/// <summary>
		/// Length of the context in bytes (8).
		/// </summary>
		public const int ContextLen = Native.CRYPTO_KDF_CONTEXTBYTES;

		/// <summary>
		/// Fills the given buffer with a new random master key (32 bytes).
		/// </summary>
		/// <param name="masterKey">The buffer to fill. Must be 32 bytes.</param>
		/// <exception cref="ArgumentException">Thrown when <paramref name="masterKey"/> is not 32 bytes.</exception>
		public static void GenerateMasterKey(Span<byte> masterKey)
		{
			if (masterKey.Length != MasterKeyLen)
				throw new ArgumentException($"Master key must be {MasterKeyLen} bytes long.", nameof(masterKey));
			LibraryInitializer.EnsureInitialized();
			Native.crypto_kdf_keygen(masterKey);
		}

		/// <summary>
		/// Fills the given buffer with a new random master key (32 bytes).
		/// </summary>
		/// <param name="masterKey">The buffer to fill. Must be 32 bytes.</param>
		/// <exception cref="ArgumentException">Thrown when <paramref name="masterKey"/> is not 32 bytes.</exception>
		public static void GenerateMasterKey(SecureMemory<byte> masterKey)
		{
			GenerateMasterKey(masterKey.AsSpan());
		}

		/// <summary>
		/// Deterministically derives a subkey from a master key, context, and subkey ID.
		/// Uses the BLAKE2b hash function internally.
		/// </summary>
		/// /// <param name="masterKey">The master key (32 bytes).</param>
		/// <param name="subkey">The buffer where the derived subkey will be written. Its length must be between 16 and 64 bytes.</param>
		/// <param name="subkeyId">The identifier for the subkey (application-defined).</param>
		/// <param name="context">8-byte context describing the usage.</param>

		/// <exception cref="ArgumentException">
		/// Thrown when <paramref name="subkey"/> is out of bounds, <paramref name="context"/> is not 8 bytes,
		/// or <paramref name="masterKey"/> is not 32 bytes.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the native key derivation fails.</exception>
		public static void DeriveSubkey(
			ReadOnlySpan<byte> masterKey,
			Span<byte> subkey,
			ulong subkeyId,
			ReadOnlySpan<byte> context)
		{
			if (subkey.Length < MinSubkeyLen || subkey.Length > MaxSubkeyLen)
				throw new ArgumentException($"Subkey length must be between {MinSubkeyLen} and {MaxSubkeyLen} bytes.", nameof(subkey));

			if (context.Length != ContextLen)
				throw new ArgumentException($"Context must be exactly {ContextLen} bytes.", nameof(context));

			if (masterKey.Length != MasterKeyLen)
				throw new ArgumentException($"Master key must be {MasterKeyLen} bytes.", nameof(masterKey));
			LibraryInitializer.EnsureInitialized();
			int rc = Native.crypto_kdf_derive_from_key(subkey, (nuint)subkey.Length, subkeyId, context, masterKey);
			if (rc != 0)
				throw new LibSodiumException("Key derivation failed.");
		}

		/// <summary>
		/// Deterministically derives a subkey from a master key, context, and subkey ID.
		/// Uses the BLAKE2b hash function internally.
		/// </summary>
		/// <param name="subkey">The buffer where the derived subkey will be written. Its length must be between 16 and 64 bytes.</param>
		/// <param name="subkeyId">The identifier for the subkey (application-defined).</param>
		/// <param name="context">8-byte context describing the usage.</param>
		/// <param name="masterKey">The master key (32 bytes).</param>
		/// <exception cref="ArgumentException">
		/// Thrown when <paramref name="subkey"/> is out of bounds, <paramref name="context"/> is not 8 bytes,
		/// or <paramref name="masterKey"/> is not 32 bytes.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the native key derivation fails.</exception>
		[Obsolete("Use the other overload instead. This will be removed in a future version.")]
		public static void DeriveSubkey(
			Span<byte> subkey,
			ulong subkeyId,
			ReadOnlySpan<byte> context,
			ReadOnlySpan<byte> masterKey)
		{
			DeriveSubkey(masterKey, subkey, subkeyId, context);
		}

		/// <summary>
		/// Deterministically derives a subkey from a master key, context, and subkey ID.
		/// Uses the BLAKE2b hash function internally.
		/// </summary>
		/// <param name="subkey">The buffer where the derived subkey will be written. Its length must be between 16 and 64 bytes.</param>
		/// <param name="subkeyId">The identifier for the subkey (application-defined).</param>
		/// <param name="context">8-byte context describing the usage.</param>
		/// <param name="masterKey">The master key (32 bytes).</param>
		/// <exception cref="ArgumentException">
		/// Thrown when <paramref name="subkey"/> is out of bounds, <paramref name="context"/> is not 8 bytes,
		/// or <paramref name="masterKey"/> is not 32 bytes.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the native key derivation fails.</exception>
		public static void DeriveSubkey(
			SecureMemory<byte> masterKey,
			SecureMemory<byte> subkey,
			ulong subkeyId,
			ReadOnlySpan<byte> context)
		{
			DeriveSubkey(masterKey.AsReadOnlySpan(), subkey.AsSpan(), subkeyId, context);
		}

		/// <summary>
		/// Deterministically derives a subkey from a master key, context, and subkey ID.
		/// Uses the BLAKE2b hash function internally.
		/// </summary>
		/// <param name="subkey">The buffer where the derived subkey will be written. Its length must be between 16 and 64 bytes.</param>
		/// <param name="subkeyId">The identifier for the subkey (application-defined).</param>
		/// <param name="context">8-byte context describing the usage.</param>
		/// <param name="masterKey">The master key (32 bytes).</param>
		/// <exception cref="ArgumentException">
		/// Thrown when <paramref name="subkey"/> is out of bounds, <paramref name="context"/> is not 8 bytes,
		/// or <paramref name="masterKey"/> is not 32 bytes.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the native key derivation fails.</exception>
		[Obsolete("Use the other overload instead. This will be removed in a future version.")]
		public static void DeriveSubkey(
			SecureMemory<byte> subkey,
			ulong subkeyId,
			ReadOnlySpan<byte> context,
			SecureMemory<byte> masterKey)
		{
			DeriveSubkey(subkey.AsSpan(), subkeyId, context, masterKey.AsReadOnlySpan());
		}

		/// <summary>
		/// Deterministically derives a subkey from a master key, using a context string whose UTF-8 representation is at most 8 bytes,
		/// and a subkey ID. If the string is shorter, it is padded with zeros. Uses the BLAKE2b hash function internally.
		/// </summary>
		/// <param name="subkey">The buffer where the derived subkey will be written. Its length must be between 16 and 64 bytes.</param>
		/// <param name="subkeyId">The identifier for the subkey (application-defined).</param>
		/// <param name="context">A string whose UTF-8 representation must be at most 8 bytes and describes the usage context.</param>
		/// <param name="masterKey">The master key (32 bytes).</param>
		/// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
		/// <exception cref="ArgumentException">
		/// Thrown when <paramref name="context"/> exceeds 8 UTF-8 bytes,
		/// or <paramref name="subkey"/> or <paramref name="masterKey"/> are of invalid length.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the native key derivation fails.</exception>
		public static void DeriveSubkey(
			ReadOnlySpan<byte> masterKey,
			Span<byte> subkey,
			ulong subkeyId,
			string context
			)
		{
			ArgumentNullException.ThrowIfNull(context);

			Span<byte> utf8Context = stackalloc byte[ContextLen];
			try
			{
				Encoding.UTF8.GetBytes(context, utf8Context);
			}
			catch (ArgumentException ex)
			{
				throw new ArgumentException($"Context must be a UTF-8 representable string of at most {ContextLen} bytes.", nameof(context), ex);
			}

			DeriveSubkey(masterKey, subkey, subkeyId, utf8Context);
		}

		/// <summary>
		/// Deterministically derives a subkey from a master key, using a context string whose UTF-8 representation is at most 8 bytes,
		/// and a subkey ID. If the string is shorter, it is padded with zeros. Uses the BLAKE2b hash function internally.
		/// </summary>
		/// <param name="subkey">The buffer where the derived subkey will be written. Its length must be between 16 and 64 bytes.</param>
		/// <param name="subkeyId">The identifier for the subkey (application-defined).</param>
		/// <param name="context">A string whose UTF-8 representation must be at most 8 bytes and describes the usage context.</param>
		/// <param name="masterKey">The master key (32 bytes).</param>
		/// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
		/// <exception cref="ArgumentException">
		/// Thrown when <paramref name="context"/> exceeds 8 UTF-8 bytes,
		/// or <paramref name="subkey"/> or <paramref name="masterKey"/> are of invalid length.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the native key derivation fails.</exception>
		[Obsolete("Use the other overload instead. This will be removed in a future version.")]
		public static void DeriveSubkey(
			Span<byte> subkey,
			ulong subkeyId,
			string context,
			ReadOnlySpan<byte> masterKey)
		{
			DeriveSubkey(masterKey, subkey, subkeyId, context);
		}

		/// <summary>
		/// Deterministically derives a subkey from a master key, using a context string whose UTF-8 representation is at most 8 bytes,
		/// and a subkey ID. If the string is shorter, it is padded with zeros. Uses the BLAKE2b hash function internally.
		/// </summary>
		/// <param name="masterKey">The master key (32 bytes).</param>
		/// <param name="subkey">The buffer where the derived subkey will be written. Its length must be between 16 and 64 bytes.</param>
		/// <param name="subkeyId">The identifier for the subkey (application-defined).</param>
		/// <param name="context">A string whose UTF-8 representation must be at most 8 bytes and describes the usage context.</param>
		/// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
		/// <exception cref="ArgumentException">
		/// Thrown when <paramref name="context"/> exceeds 8 UTF-8 bytes,
		/// or <paramref name="subkey"/> or <paramref name="masterKey"/> are of invalid length.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the native key derivation fails.</exception>
		public static void DeriveSubkey(
			SecureMemory<byte> masterKey,
			SecureMemory<byte> subkey,
			ulong subkeyId,
			string context
			)
		{
			DeriveSubkey(masterKey.AsReadOnlySpan(), subkey.AsSpan(), subkeyId, context);
		}

		/// <summary>
		/// Deterministically derives a subkey from a master key, using a context string whose UTF-8 representation is at most 8 bytes,
		/// and a subkey ID. If the string is shorter, it is padded with zeros. Uses the BLAKE2b hash function internally.
		/// </summary>
		/// <param name="subkey">The buffer where the derived subkey will be written. Its length must be between 16 and 64 bytes.</param>
		/// <param name="subkeyId">The identifier for the subkey (application-defined).</param>
		/// <param name="context">A string whose UTF-8 representation must be at most 8 bytes and describes the usage context.</param>
		/// <param name="masterKey">The master key (32 bytes).</param>
		/// <exception cref="ArgumentNullException">Thrown when <paramref name="context"/> is null.</exception>
		/// <exception cref="ArgumentException">
		/// Thrown when <paramref name="context"/> exceeds 8 UTF-8 bytes,
		/// or <paramref name="subkey"/> or <paramref name="masterKey"/> are of invalid length.
		/// </exception>
		/// <exception cref="LibSodiumException">Thrown if the native key derivation fails.</exception>
		[Obsolete("Use the other overload instead. This will be removed in a future version.")]
		public static void DeriveSubkey(
			SecureMemory<byte> subkey,
			ulong subkeyId,
			string context,
			SecureMemory<byte> masterKey)
		{
			DeriveSubkey(masterKey.AsReadOnlySpan(), subkey.AsSpan(), subkeyId, context);
		}
	}
}
