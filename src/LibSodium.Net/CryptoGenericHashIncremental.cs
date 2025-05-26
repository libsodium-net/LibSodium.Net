using LibSodium.Interop;
using System.Runtime.InteropServices;

namespace LibSodium
{
	internal sealed class CryptoGenericHashIncremental : ICryptoIncrementalHash
	{
		private  Native.crypto_generichash_blake2b_state state;
		private bool isDisposed = false;
		private bool isFinalized = false;
		private readonly int hashLen;

		public CryptoGenericHashIncremental(ReadOnlySpan<byte> key, int hashLen)
		{
			this.hashLen = hashLen;
			if (key.Length != 0 && (key.Length < CryptoGenericHash.MinKeyLen || key.Length > CryptoGenericHash.MaxKeyLen))
			{
				throw new ArgumentOutOfRangeException($"Key length must be between {CryptoGenericHash.MinKeyLen} and {CryptoGenericHash.MaxKeyLen} bytes.", nameof(key));
			}
			if (hashLen < CryptoGenericHash.MinHashLen || hashLen > CryptoGenericHash.MaxHashLen)
			{
				throw new ArgumentException($"Hash length must be between {CryptoGenericHash.MinHashLen} and {CryptoGenericHash.MaxHashLen} bytes.", nameof(hashLen));
			}
			if (Native.crypto_generichash_init(ref state, key, (nuint) key.Length, (nuint) hashLen) != 0)
			{
				throw new LibSodiumException("Failed to initialize incremental hashing.");
			}
		}

		private void CheckDisposed()
		{
			if (isDisposed)
			{
				throw new ObjectDisposedException(nameof(CryptoGenericHashIncremental), "The incremental hash has already been disposed.");
			}
		}

		public void Update(ReadOnlySpan<byte> data)
		{
			CheckDisposed();
			if (isFinalized)
			{
				throw new InvalidOperationException("Cannot update a finalized hash");
			}
			int result = Native.crypto_generichash_update(ref state, data, (ulong)data.Length);
			if (result != 0)
				throw new LibSodiumException("Failed to update the incremental hashing operation.");
		}

		public void Final(Span<byte> hash)
		{
			CheckDisposed();
			if (isFinalized)
			{
				throw new InvalidOperationException("Hash has already been finalized.");
			}
			if (hash.Length != hashLen)
			{
				throw new ArgumentException($"Hash must be exactly {hashLen} bytes, matching the hash length specified at construction.", nameof(hash));
			}
			int result = Native.crypto_generichash_final(ref state, hash, (nuint)hashLen);
			if (result != 0)
			{
				throw new LibSodiumException("Failed to finalize the incremental hashing operation.");
			}
			SecureMemory.MemZero(ref state); // Clear the state to prevent sensitive data leakage
			isFinalized = true;
		}

		public void Dispose()
		{
			if (isDisposed) return;
			isDisposed = true;
			if (!isFinalized)
			{
				SecureMemory.MemZero(ref state); // Clear the state to prevent sensitive data leakage
			}
		}
	}
}
