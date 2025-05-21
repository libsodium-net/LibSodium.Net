using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace LibSodium;

/// <summary>
/// Provides a generic interface for stream ciphers like XSalsa20, ChaCha20, etc.
/// </summary>
/// <typeparam name="T">The cipher implementation (e.g., <see cref="LowLevel.XSalsa20Cipher"/>).</typeparam>
internal static class CryptoStreamCipher<T> where T : struct, LowLevel.IStreamCipher
{
	public static readonly int KeyLen = T.KeyLen;
	public static readonly int NonceLen = T.NonceLen;
	public static readonly int BlockLen = T.BlockLen;
	private const int DefaultBufferSize = 8192;

	public static void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ulong initialCounter = 0UL)
		=> Xor(key, nonce, plaintext, ciphertext, initialCounter);

	public static void Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ulong initialCounter = 0UL)
		=> Xor(key, nonce, ciphertext, plaintext, initialCounter);

	private static void Xor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output, ulong initialCounter = 0)
	{
		if (key.Length != KeyLen) throw new ArgumentException($"Key must be {KeyLen} bytes", nameof(key));
		if (nonce.Length != NonceLen) throw new ArgumentException($"Nonce must be {NonceLen} bytes", nameof(nonce));
		if (output.Length < input.Length) throw new ArgumentException("Output buffer too small", nameof(output));

		LibraryInitializer.EnsureInitialized();
		if (initialCounter == 0)
		{
			if (T.Xor(output.Slice(0, input.Length), input, nonce, key) != 0)
				throw new LibSodiumException("Stream cipher XOR failed.");
		}
		else
		{
			if (T.Xor(output.Slice(0, input.Length), input, nonce, key, initialCounter) != 0)
				throw new LibSodiumException("Stream cipher XOR failed.");
		}
	}

	public static void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Stream input, Stream output)
		=> Xor(key, nonce, input, output);

	public static void Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Stream input, Stream output)
		=> Xor(key, nonce, input, output);

	public static void GenerateKeystream(Span<byte> output, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
	{
		if (key.Length != KeyLen) throw new ArgumentException($"Key must be {KeyLen} bytes", nameof(key));
		if (nonce.Length != NonceLen) throw new ArgumentException($"Nonce must be {NonceLen} bytes", nameof(nonce));

		LibraryInitializer.EnsureInitialized();
		if (T.GenerateKeystream(output, nonce, key) != 0)
			throw new LibSodiumException("Keystream generation failed.");
	}

	public static async Task EncryptAsync(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> nonce, Stream input, Stream output, CancellationToken cancellationToken = default)
		=> await XorAsync(key, nonce, input, output, cancellationToken);

	public static async Task DecryptAsync(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> nonce, Stream input, Stream output, CancellationToken cancellationToken = default)
		=> await XorAsync(key, nonce, input, output, cancellationToken);

	private static void Xor(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Stream input, Stream output)
	{
		if (key.Length != KeyLen) throw new ArgumentException($"Key must be {KeyLen} bytes", nameof(key));
		if (nonce.Length != NonceLen) throw new ArgumentException($"Nonce must be {NonceLen} bytes", nameof(nonce));
		if (input is null || output is null) throw new ArgumentNullException();

		LibraryInitializer.EnsureInitialized();

		byte[] inputBuffer = System.Buffers.ArrayPool<byte>.Shared.Rent(DefaultBufferSize);
		byte[] outputBuffer = System.Buffers.ArrayPool<byte>.Shared.Rent(DefaultBufferSize);
		ulong ic = 0;

		try
		{
			while (true)
			{
				int read = input.Fill(inputBuffer, 0, DefaultBufferSize);
				if (read == 0) break;
				if (T.Xor(outputBuffer.AsSpan(0, read), inputBuffer.AsSpan(0, read), nonce, key, ic) != 0)
					throw new LibSodiumException("Stream cipher XOR failed.");

				output.Write(outputBuffer, 0, read);
				ic += (ulong)(read / BlockLen);
			}
		}
		finally
		{
			System.Buffers.ArrayPool<byte>.Shared.Return(inputBuffer);
			System.Buffers.ArrayPool<byte>.Shared.Return(outputBuffer);
		}
	}

	private static async Task XorAsync(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> nonce, Stream input, Stream output, CancellationToken cancellationToken)
	{
		if (key.Length != KeyLen) throw new ArgumentException($"Key must be {KeyLen} bytes", nameof(key));
		if (nonce.Length != NonceLen) throw new ArgumentException($"Nonce must be {NonceLen} bytes", nameof(nonce));
		if (input is null || output is null) throw new ArgumentNullException();

		LibraryInitializer.EnsureInitialized();

		byte[] buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(DefaultBufferSize);
		byte[] result = System.Buffers.ArrayPool<byte>.Shared.Rent(DefaultBufferSize);
		ulong ic = 0;

		try
		{
			while (true)
			{
				int read = await input.FillAsync(buffer, 0, DefaultBufferSize, cancellationToken).ConfigureAwait(false);
				if (read == 0) break;
				if (T.Xor(result.AsSpan(0, read), buffer.AsSpan(0, read), nonce.Span, key.Span, ic) != 0)
					throw new LibSodiumException("Stream cipher XOR failed.");

				await output.WriteAsync(result.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
				ic += (ulong)(read / BlockLen);
			}
		}
		finally
		{
			System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
			System.Buffers.ArrayPool<byte>.Shared.Return(result);
		}
	}
}
