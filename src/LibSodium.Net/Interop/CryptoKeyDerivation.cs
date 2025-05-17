using System.Runtime.InteropServices;

namespace LibSodium.Interop
{
	internal static partial class Native
	{
		public const string CRYPTO_KDF_PRIMITIVE = "blake2b";
		public const int CRYPTO_KDF_BYTES_MIN = 16;
		public const int CRYPTO_KDF_BYTES_MAX = 64;
		public const int CRYPTO_KDF_CONTEXTBYTES = 8;
		public const int CRYPTO_KDF_KEYBYTES = 32;

		/// <summary>
		/// Generates a random master key for use with crypto_kdf_derive_from_key.
		/// </summary>
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_keygen))]
		internal static partial void crypto_kdf_keygen(Span<byte> key);

		/// <summary>
		/// Derives a subkey from a master key.
		/// </summary>
		/// <param name="subkey">Output buffer for the derived subkey.</param>
		/// <param name="subkeyLen">Length of the subkey to derive.</param>
		/// <param name="subkeyId">Unique identifier for the subkey.</param>
		/// <param name="context">8-byte context string to namespace subkeys.</param>
		/// <param name="masterKey">The 32-byte master key.</param>
		/// <returns>0 on success, -1 on failure.</returns>
		[LibraryImport(LibSodiumNativeLibraryName, EntryPoint = nameof(crypto_kdf_derive_from_key))]
		internal static partial int crypto_kdf_derive_from_key(
			Span<byte> subkey,
			nuint subkeyLen,
			ulong subkeyId,
			ReadOnlySpan<byte> context,
			ReadOnlySpan<byte> masterKey);
	}
}
