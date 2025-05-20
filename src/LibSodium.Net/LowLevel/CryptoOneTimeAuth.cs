using LibSodium.Interop;

namespace LibSodium.LowLevel;

/// <summary>
/// Implements one-time authentication using Poly1305, via the crypto_onetimeauth API.
/// </summary>
internal readonly struct CryptoOneTimeAuth : IMac
{
	/// <summary>
	/// Length of the MAC in bytes (16).
	/// </summary>
	public static int MacLen => Native.CRYPTO_ONETIMEAUTH_BYTES;

	/// <summary>
	/// Length of the secret key in bytes (32).
	/// </summary>
	public static int KeyLen => Native.CRYPTO_ONETIMEAUTH_KEYBYTES;

	/// <summary>
	/// Length of the internal state in bytes (per crypto_onetimeauth_statebytes()).
	/// </summary>
	public static int StateLen => (int)Native.crypto_onetimeauth_statebytes();

	public static int ComputeMac(Span<byte> mac, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
		=> Native.crypto_onetimeauth(mac, message, (ulong)message.Length, key);

	public static int VerifyMac(ReadOnlySpan<byte> mac, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
		=> Native.crypto_onetimeauth_verify(mac, message, (ulong)message.Length, key);

	public static int Init(Span<byte> state, ReadOnlySpan<byte> key)
		=> Native.crypto_onetimeauth_init(state, key);

	public static int Update(Span<byte> state, ReadOnlySpan<byte> message)
		=> Native.crypto_onetimeauth_update(state, message, (ulong)message.Length);

	public static int Final(Span<byte> state, Span<byte> mac)
		=> Native.crypto_onetimeauth_final(state, mac);

	public static void GenerateKey(Span<byte> key)
		=> RandomGenerator.Fill(key); // No keygen API for crypto_onetimeauth
}
