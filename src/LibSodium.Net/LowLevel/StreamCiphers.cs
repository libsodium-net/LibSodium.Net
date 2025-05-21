using LibSodium.Interop;

namespace LibSodium.LowLevel;

internal readonly struct XSalsa20Cipher : IStreamCipher
{
	public static int KeyLen => Native.CRYPTO_STREAM_XSALSA20_KEYBYTES;
	public static int NonceLen => Native.CRYPTO_STREAM_XSALSA20_NONCEBYTES;
	public static int BlockLen => 64;

	public static int Xor(Span<byte> output, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
		=> Native.crypto_stream_xsalsa20_xor(output, message, (ulong)message.Length, nonce, key);

	public static int Xor(Span<byte> output, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ulong initialCounter)
		=> Native.crypto_stream_xsalsa20_xor_ic(output, message, (ulong)message.Length, nonce, initialCounter, key);

	public static int GenerateKeystream(Span<byte> output, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
		=> Native.crypto_stream_xsalsa20(output, (ulong)output.Length, nonce, key);
}

internal readonly struct Salsa20Cipher : IStreamCipher
{
	public static int KeyLen => Native.CRYPTO_STREAM_SALSA20_KEYBYTES;
	public static int NonceLen => Native.CRYPTO_STREAM_SALSA20_NONCEBYTES;
	public static int BlockLen => 64;

	public static int Xor(Span<byte> output, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
		=> Native.crypto_stream_salsa20_xor(output, message, (ulong)message.Length, nonce, key);

	public static int Xor(Span<byte> output, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ulong initialCounter)
		=> Native.crypto_stream_salsa20_xor_ic(output, message, (ulong)message.Length, nonce, initialCounter, key);

	public static int GenerateKeystream(Span<byte> output, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
		=> Native.crypto_stream_salsa20(output, (ulong)output.Length, nonce, key);
}

internal readonly struct ChaCha20Cipher : IStreamCipher
{
	public static int KeyLen => Native.CRYPTO_STREAM_CHACHA20_KEYBYTES;
	public static int NonceLen => Native.CRYPTO_STREAM_CHACHA20_NONCEBYTES;
	public static int BlockLen => 64;

	public static int Xor(Span<byte> output, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
		=> Native.crypto_stream_chacha20_xor(output, message, (ulong)message.Length, nonce, key);

	public static int Xor(Span<byte> output, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ulong initialCounter)
		=> Native.crypto_stream_chacha20_xor_ic(output, message, (ulong)message.Length, nonce, initialCounter, key);

	public static int GenerateKeystream(Span<byte> output, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
		=> Native.crypto_stream_chacha20(output, (ulong)output.Length, nonce, key);
}

internal readonly struct XChaCha20Cipher : IStreamCipher
{
	public static int KeyLen => Native.CRYPTO_STREAM_XChaCha20_KEYBYTES;
	public static int NonceLen => Native.CRYPTO_STREAM_XChaCha20_NONCEBYTES;
	public static int BlockLen => 64;

	public static int Xor(Span<byte> output, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
		=> Native.crypto_stream_xchacha20_xor(output, message, (ulong)message.Length, nonce, key);

	public static int Xor(Span<byte> output, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ulong initialCounter)
		=> Native.crypto_stream_xchacha20_xor_ic(output, message, (ulong)message.Length, nonce, initialCounter, key);

	public static int GenerateKeystream(Span<byte> output, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
		=> Native.crypto_stream_xchacha20(output, (ulong)output.Length, nonce, key);
}

internal readonly struct ChaCha20IetfCipher : IStreamCipher
{
	public static int KeyLen => Native.CRYPTO_STREAM_CHACHA20_IETF_KEYBYTES;
	public static int NonceLen => Native.CRYPTO_STREAM_CHACHA20_IETF_NONCEBYTES;
	public static int BlockLen => 64;

	public static int Xor(Span<byte> output, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
		=> Native.crypto_stream_chacha20_ietf_xor(output, message, (ulong)message.Length, nonce, key);

	public static int Xor(Span<byte> output, ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ulong initialCounter)
		=> Native.crypto_stream_chacha20_ietf_xor_ic(output, message, (ulong)message.Length, nonce, (uint)initialCounter, key);

	public static int GenerateKeystream(Span<byte> output, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
		=> Native.crypto_stream_chacha20_ietf(output, (ulong)output.Length, nonce, key);
}