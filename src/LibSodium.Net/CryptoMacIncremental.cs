using LibSodium.Interop;
using LibSodium.LowLevel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LibSodium
{
	internal sealed class CryptoMacIncremental<T> : ICryptoIncrementalHash where T : IMac
	{

		private readonly byte[] state = new byte[T.StateLen];
		private bool isDisposed = false;
		private bool isFinalized = false;

		public CryptoMacIncremental(ReadOnlySpan<byte> key)
		{
			if (key.Length != T.KeyLen)
			{
				throw new ArgumentOutOfRangeException($"Key length must be exactly {T.KeyLen} bytes.", nameof(key));
			}
			if (T.Init(state, key) != 0)
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
				SecureMemory.MemZero(state); // Clear the state to prevent sensitive data leakage
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
			int result = T.Final(state, hash);
			if (result != 0)
			{
				throw new LibSodiumException("Failed to finalize the incremental hashing operation.");
			}
			SecureMemory.MemZero(state); // Clear the state to prevent sensitive data leakage
			isFinalized = true;
		}

		public void Update(ReadOnlySpan<byte> data)
		{
			CheckDisposed();
			if (isFinalized)
			{
				throw new InvalidOperationException("Cannot update a finalized hash");
			}
			int result = T.Update(state, data);
			if (result != 0)
				throw new LibSodiumException("Failed to update the incremental hashing operation.");
		}
	}
}
