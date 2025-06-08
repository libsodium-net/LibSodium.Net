using LibSodium.Interop;

namespace LibSodium;

/// <summary>
/// Incremental signature generator using Ed25519 over SHA-512.
/// </summary>
internal sealed class CryptoSignIncremental : ICryptoIncrementalOperation
{
	private byte[] state;
	private readonly ReadOnlyMemory<byte> privateKey;
	private bool isDisposed = false;
	private bool isFinalized = false;

	/// <summary>
	/// Initializes a new incremental signature session with the specified Ed25519 private key.
	/// </summary>
	/// <param name="privateKey">The Ed25519 private key (64 bytes).</param>
	/// <exception cref="ArgumentException">If the key is not 64 bytes long.</exception>
	/// <exception cref="LibSodiumException">If initialization fails internally.</exception>
	public CryptoSignIncremental(ReadOnlyMemory<byte> privateKey)
	{
		if (privateKey.Length != CryptoSign.PrivateKeyLen)
			throw new ArgumentException($"Private key must be {CryptoSign.PrivateKeyLen} bytes", nameof(privateKey));

		this.privateKey = privateKey;
		state = new byte[CryptoSign.StateLen];

		if (Native.crypto_sign_init(state) != 0)
			throw new LibSodiumException("Failed to initialize incremental crypto sign operation");
	}

	private void CheckDisposed()
	{
		if (isDisposed)
		{
			throw new ObjectDisposedException(nameof(CryptoSignIncremental), "The incremental crypto sign operation has already been disposed.");
		}
	}

	public void Update(ReadOnlySpan<byte> data)
	{
		CheckDisposed();
		if (isFinalized)
			throw new InvalidOperationException("Update called after finalization.");

		if (Native.crypto_sign_update(state, data, (nuint)data.Length) != 0)
			throw new LibSodiumException("Failed to update the incremental crypto sign operation.");
	}

	/// <inheritdoc/>
	public void Final(Span<byte> result)
	{
		CheckDisposed();
		if (isFinalized)
			throw new InvalidOperationException("Final has already been called.");
		if (result.Length < CryptoSign.SignatureLen)
			throw new ArgumentOutOfRangeException(nameof(result), $"Signature buffer must be at least {CryptoSign.SignatureLen} bytes");
		ulong siglen;
		if (Native.crypto_sign_final_create(state, result, out siglen, privateKey.Span) != 0)
			throw new LibSodiumException(nameof(Native.crypto_sign_final_create));
		if (siglen != CryptoSign.SignatureLen)
			throw new LibSodiumException("Unexpected signature length returned by native call.");
		SecureMemory.MemZero(state); // Clear the state to prevent sensitive data leakage
		isFinalized = true;
	}

	/// <inheritdoc/>
	public void Dispose()
	{
		if (isDisposed) return;
		isDisposed = true;
		if (!isFinalized)
		{
			SecureMemory.MemZero(state); // Clear the state to prevent sensitive data leakage
		}
	}
}
