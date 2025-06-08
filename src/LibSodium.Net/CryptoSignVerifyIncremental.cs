using LibSodium.Interop;

namespace LibSodium;

/// <summary>
/// Incremental signature generator using Ed25519 over SHA-512.
/// </summary>
internal sealed class CryptoSignVerifyIncremental : ICryptoIncrementalOperation
{
	private readonly byte[] state;
	private readonly ReadOnlyMemory<byte> publicKey;
	private readonly ReadOnlyMemory<byte> signature;
	private bool isDisposed = false;
	private bool isFinalized = false;

	public CryptoSignVerifyIncremental(ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> signature)
	{
		if (publicKey.Length != CryptoSign.PublicKeyLen)
			throw new ArgumentException($"public key must be {CryptoSign.PublicKeyLen} bytes", nameof(publicKey));

		if (signature.Length != CryptoSign.SignatureLen)
			throw new ArgumentException($"Signature must be {CryptoSign.SignatureLen} bytes", nameof(signature));

		this.publicKey = publicKey;
		this.signature = signature;

		this.state = new byte[CryptoSign.StateLen];

		if (Native.crypto_sign_init(state) != 0)
			throw new LibSodiumException("Failed to initialize incremental crypto sign operation");

	}

	private void CheckDisposed()
	{
		if (isDisposed)
		{
			throw new ObjectDisposedException(nameof(CryptoSignVerifyIncremental), "The incremental crypto sign operation has already been disposed.");
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
		if (result.Length == 0 )
			throw new ArgumentOutOfRangeException(nameof(result), $"result buffer must not be empty");
		result[0] = (byte)Native.crypto_sign_final_verify(state, signature.Span, publicKey.Span) == 0 ? (byte)1: (byte) 0 ;
		isFinalized = true;
	}

	/// <inheritdoc/>
	public void Dispose()
	{
		isDisposed = true;
	}
}
