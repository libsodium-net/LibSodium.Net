using LibSodium.Interop;

namespace LibSodium.LowLevel;

internal readonly struct HmacSha256 : IMac
{
	public static int MacLen => Native.CRYPTO_AUTH_HMACSHA256_BYTES;
	public static int KeyLen => Native.CRYPTO_AUTH_HMACSHA256_KEYBYTES;
	public static int StateLen => (int)Native.crypto_auth_hmacsha256_statebytes();

	public static int ComputeMac(Span<byte> mac, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
		=> Native.crypto_auth_hmacsha256(mac, message, (ulong)message.Length, key);

	public static int VerifyMac(ReadOnlySpan<byte> mac, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
		=> Native.crypto_auth_hmacsha256_verify(mac, message, (ulong)message.Length, key);

	public static int Init(Span<byte> state, ReadOnlySpan<byte> key)
		=> Native.crypto_auth_hmacsha256_init(state, key, (nuint)key.Length);

	public static int Update(Span<byte> state, ReadOnlySpan<byte> message)
		=> Native.crypto_auth_hmacsha256_update(state, message, (ulong)message.Length);

	public static int Final(Span<byte> state, Span<byte> mac)
		=> Native.crypto_auth_hmacsha256_final(state, mac);

	public static void GenerateKey(Span<byte> key)
		=> Native.crypto_auth_hmacsha256_keygen(key);
}
