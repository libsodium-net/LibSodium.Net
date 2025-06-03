
using LibSodium.Interop;
using System.Text;

namespace LibSodium;
/// <summary>
/// Deterministically derives 32-byte subkeys using the HChaCha20 core function from a key, a salt-like input and optional domain context.
/// </summary>
public static class CryptoHChaCha20
{
	/// <summary>
	/// Length of the input (16 bytes).
	/// </summary>
	public const int InputLen = Native.CRYPTO_CORE_HCHACHA20_INPUTBYTES;

	/// <summary>
	/// Length of the master key (32 bytes).
	/// </summary>
	public const int KeyLen = Native.CRYPTO_CORE_HCHACHA20_KEYBYTES;

	/// <summary>
	/// Length of the derived subkey (32 bytes).
	/// </summary>
	public const int SubKeyLen = Native.CRYPTO_CORE_HCHACHA20_OUTPUTBYTES;

	/// <summary>
	/// Length of the context (16 bytes), used for domain separation.
	/// </summary>
	public const int ContextLen = Native.CRYPTO_CORE_HCHACHA20_CONSTBYTES;

	/// <summary>
	/// Derives a 32-byte subkey from a master key using the HChaCha20 function. 
	/// This function is suitable for fast, deterministic key derivation with domain separation.
	/// </summary>
	/// <param name="masterKey">The 32-byte master key.</param>
	/// <param name="subKey">The output buffer for the derived subkey (must be exactly 32 bytes).</param>
	/// <param name="input">
	/// A 16-byte salt-like input used to calculate the subkey. 
	/// </param>
	/// <param name="context">
	/// An optional 16-byte context used for domain separation. 
	/// If not provided, libsodium uses an internal default.
	/// </param>
	/// <exception cref="ArgumentException">Thrown if any parameter has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the native function fails.</exception>
	public static void DeriveSubkey(
		ReadOnlySpan<byte> masterKey,
		Span<byte> subKey,
		ReadOnlySpan<byte> input,
		ReadOnlySpan<byte> context = default)
	{
		if (masterKey.Length != KeyLen)
			throw new ArgumentException($"Master key must be exactly {KeyLen} bytes.", nameof(masterKey));
		if (subKey.Length != SubKeyLen)
			throw new ArgumentException($"Subkey must be exactly {SubKeyLen} bytes.", nameof(subKey));
		if (input.Length != InputLen)
			throw new ArgumentException($"Input must be exactly {InputLen} bytes.", nameof(input));
		if (context.Length != 0 && context.Length != ContextLen)
			throw new ArgumentException("Context must be either empty or exactly 16 bytes.", nameof(context));


		LibraryInitializer.EnsureInitialized();

		int rc = Native.crypto_core_hchacha20(subKey, input, masterKey, context);
		if (rc != 0)
			throw new LibSodiumException("crypto_core_hchacha20 failed.");
	}

	/// <summary>
	/// Derives a 32-byte subkey from a master key using the HChaCha20 function. 
	/// This function is suitable for fast, deterministic key derivation with domain separation.
	/// </summary>
	/// <param name="masterKey">The 32-byte master key.</param>
	/// <param name="subKey">The output buffer for the derived subkey (must be exactly 32 bytes).</param>
	/// <param name="input">
	/// A 16-byte salt-like input used to calculate the subkey. 
	/// </param>
	/// <param name="context">
	/// A string whose UTF-8 representation must not exceed 16 bytes. This is used for domain separation.
	/// </param>
	/// <exception cref="ArgumentException">Thrown if any parameter has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the native function fails.</exception>
	public static void DeriveSubkey(
		ReadOnlySpan<byte> masterKey,
		Span<byte> subKey,
		ReadOnlySpan<byte> input,
		string context)
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

		DeriveSubkey(masterKey, subKey, input, utf8Context);
	}

	/// <summary>
	/// Derives a 32-byte subkey from a master key using the HChaCha20 function. 
	/// This function is suitable for fast, deterministic key derivation with domain separation.
	/// </summary>
	/// <param name="masterKey">The 32-byte master key stored in secure memory.</param>
	/// <param name="subKey">The secure memory output buffer for the derived subkey (must be exactly 32 bytes).</param>
	/// <param name="input">A 16-byte salt-like input used to calculate the subkey.</param>
	/// <param name="context">
	/// A string whose UTF-8 representation must not exceed 16 bytes. This is used for domain separation.
	/// </param>
	/// <exception cref="ArgumentException">Thrown if any parameter has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the native function fails.</exception>
	public static void DeriveSubkey(
		SecureMemory<byte> masterKey,
		SecureMemory<byte> subKey,
		ReadOnlySpan<byte> input,
		string context)
	{
		DeriveSubkey(masterKey.AsReadOnlySpan(), subKey.AsSpan(), input, context);
	}


	/// <summary>
	/// Derives a 32-byte subkey from a master key using the HChaCha20 function. 
	/// This function is suitable for fast, deterministic key derivation with domain separation.
	/// </summary>
	/// <param name="masterKey">The 32-byte master key stored in secure memory.</param>
	/// <param name="subKey">The secure memory output buffer for the derived subkey (must be exactly 32 bytes).</param>
	/// <param name="input">
	/// A 16-byte salt-like input used to calculate the subkey.
	/// </param>
	/// <param name="context">
	/// An optional 16-byte context used for domain separation. 
	/// If not provided, libsodium uses an internal default.
	/// </param>
	/// <exception cref="ArgumentException">Thrown if any parameter has an invalid length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the native function fails.</exception>
	public static void DeriveSubkey(
		SecureMemory<byte> masterKey,
		SecureMemory<byte> subKey,
		ReadOnlySpan<byte> input,
		ReadOnlySpan<byte> context = default)
	{
		DeriveSubkey(masterKey.AsReadOnlySpan(), subKey.AsSpan(), input, context);
	}
}
