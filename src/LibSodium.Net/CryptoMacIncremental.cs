using LibSodium.LowLevel;

namespace LibSodium
{
	internal sealed class CryptoMacIncremental<T> : ICryptoIncrementalOperation where T : IMac
	{

		private readonly SecureMemory<byte> state = SecureMemory.Create<byte>(T.StateLen);
		private bool isDisposed = false;
		private bool isFinalized = false;

		public CryptoMacIncremental(ReadOnlySpan<byte> key)
		{
			if (key.Length != T.KeyLen)
			{
				throw new ArgumentOutOfRangeException($"Key length must be exactly {T.KeyLen} bytes.", nameof(key));
			}
			if (T.Init(state.AsSpan(), key) != 0)
			{
				throw new LibSodiumException("Failed to initialize incremental hashing.");
			}
		}

		private void CheckDisposed()
		{
			if (isDisposed)
			{
				throw new ObjectDisposedException(nameof(CryptoMacIncremental<T>), "The incremental hash has already been disposed.");
			}
		}
		public void Dispose()
		{
			if (isDisposed) return;
			isDisposed = true;
			if (!isFinalized)
			{
				state.Dispose(); // Clear the state to prevent sensitive data leakage
			}
		}

		public void Final(Span<byte> hash)
		{
			CheckDisposed();
			if (isFinalized)
			{
				throw new InvalidOperationException("Hash has already been finalized.");
			}
			if (hash.Length != T.MacLen)
			{
				throw new ArgumentException($"Hash must be exactly {T.MacLen} bytes.", nameof(hash));
			}
			int result = T.Final(state.AsSpan(), hash);
			if (result != 0)
			{
				throw new LibSodiumException("Failed to finalize the incremental hashing operation.");
			}
			state.Dispose(); // Clear the state to prevent sensitive data leakage
			isFinalized = true;
		}

		public void Update(ReadOnlySpan<byte> data)
		{
			CheckDisposed();
			if (isFinalized)
			{
				throw new InvalidOperationException("Cannot update a finalized hash");
			}
			int result = T.Update(state.AsSpan(), data);
			if (result != 0)
				throw new LibSodiumException("Failed to update the incremental hashing operation.");
		}
	}
}
