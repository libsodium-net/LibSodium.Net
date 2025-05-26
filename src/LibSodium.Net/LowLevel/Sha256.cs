using LibSodium.Interop;

namespace LibSodium.LowLevel;

/// <summary>
/// Low-level wrapper for libsodium’s SHA‑256 implementation.
/// </summary>
internal readonly struct Sha256 : IKeyLessHash
{
	public static int HashLen => Native.CRYPTO_HASH_SHA256_BYTES;
	public static int StateLen => (int)Native.crypto_hash_sha256_statebytes();

	public static int ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
		=> Native.crypto_hash_sha256(hash, message, (ulong)message.Length);

	public static int Init(Span<byte> state)
		=> Native.crypto_hash_sha256_init(state);

	public static int Update(Span<byte> state, ReadOnlySpan<byte> message)
		=> Native.crypto_hash_sha256_update(state, message, (ulong)message.Length);

	public static int Final(Span<byte> state, Span<byte> hash)
		=> Native.crypto_hash_sha256_final(state, hash);
}
