#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member


using System.Buffers;
using System.Security.Cryptography;

namespace LibSodium;

/// <summary>
/// Provides high-level, stream-based authenticated encryption and decryption
/// using the XChaCha20-Poly1305 algorithm. This class abstracts the complexity
/// of securely processing large data streams, including chunking, authentication,
/// and cryptographic state management.
/// </summary>
/// <remarks>
/// <para>
/// This class is built on LibSodium’s <c>crypto_secretstream_xchacha20poly1305</c> API,
/// using XChaCha20 for encryption and Poly1305 for message authentication. The large
/// 192-bit nonce (24 bytes) virtually eliminates the risk of nonce reuse when generated randomly.
/// </para>
/// <para>
/// The stream is processed in fixed-size chunks (64 KB), each individually encrypted
/// and authenticated. A randomly generated header (nonce and metadata) is prepended
/// to the stream and required for successful decryption.
/// </para>
/// <para>
/// <b>Security Considerations:</b>
/// <list type="bullet">
/// <item><b>Key Management:</b> Keys must be generated securely and stored safely.
/// Compromise of the key invalidates confidentiality and integrity guarantees.</item>
/// <item><b>Nonce Handling:</b> Nonces are generated internally. Do not reuse headers
/// or keys manually unless you know what you're doing.</item>
/// <item><b>Integrity:</b> Poly1305 tags ensure tampering is detected during decryption.
/// Any modification will result in decryption failure.</item>
/// </list>
/// </para>
/// </remarks>
public static class SecretStream

{
	/// <summary>
	/// The size of each plaintext chunk processed during encryption (64KB).
	/// This chunk size is used to divide the input stream into manageable blocks.
	/// </summary>
	public const int PlainChunkSize = 64 * 1024; // 64KB

	/// <summary>
	/// The size of each ciphertext chunk written to the output stream. This includes
	/// the size of the corresponding plaintext chunk plus the overhead added by the
	/// encryption and authentication process (typically 17 bytes for XChaCha20-Poly1305).
	/// </summary>
	private static readonly int CipherChunkSize = PlainChunkSize + CryptoSecretStream.OverheadLen;


	/// <summary>
	/// Asynchronously encrypts data from the <paramref name="input"/> stream and writes the ciphertext
	/// to the <paramref name="output"/> stream using the XChaCha20-Poly1305 algorithm.
	/// </summary>
	/// <param name="input">The readable stream containing plaintext to encrypt.</param>
	/// <param name="output">The writable stream where ciphertext will be written.</param>
	/// <param name="key">
	/// The secret key for encryption. Must be securely generated and kept confidential.
	/// Typically 32 bytes in length for XChaCha20-Poly1305.
	/// </param>
	/// <param name="cancellationToken">Optional token to cancel the asynchronous operation.</param>
	/// <returns>A task representing the asynchronous encryption process.</returns>
	/// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
	/// <exception cref="OperationCanceledException">Thrown if the operation is canceled.</exception>
	/// <remarks>
	/// <para>
	/// The input stream is read in <see cref="PlainChunkSize"/> blocks. Each block is encrypted
	/// and written to the output stream with an authentication tag to ensure integrity.
	/// </para>
	/// <para>
	/// A cryptographic header (including a randomly generated nonce) is prepended to the output.
	/// This header is required for successful decryption.
	/// </para>
	/// <para>
	/// The encryption state is maintained internally and finalized when the last chunk is written
	/// with the <see cref="CryptoSecretStreamTag.Final"/> tag.
	/// </para>
	/// <para>
	/// <b>Note:</b> The caller is responsible for managing the lifetime of the input/output streams.
	/// They are not closed or disposed automatically.
	/// </para>
	/// </remarks>
	public static async Task EncryptAsync(
		Stream input,
		Stream output,
		ReadOnlyMemory<byte> key,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(input, nameof(input));
		ArgumentNullException.ThrowIfNull(output, nameof(output));
		ArgumentNullException.ThrowIfNull(key, nameof(key));
		byte[]? cipherBuffer = null;
		byte[]? plainBuffer = null;
		try
		{
			cipherBuffer = ArrayPool<byte>.Shared.Rent(CipherChunkSize);
			plainBuffer = ArrayPool<byte>.Shared.Rent(PlainChunkSize);
		}
		catch
		{
			TryReturnBuffers(cipherBuffer, plainBuffer);
			throw;
		}
		byte[] stateBuffer = new byte[CryptoSecretStream.StateLen];
		byte[] headerBuffer = new byte[CryptoSecretStream.HeaderLen];

		try
		{
			CryptoSecretStream.InitializeEncryption(stateBuffer, headerBuffer, key.Span);
			await output.WriteAsync(headerBuffer, cancellationToken).ConfigureAwait(false);

			int bufferFill = 0;
			bool endOfStream = false;

			while (!endOfStream)
			{
				bufferFill = await FillBufferAsync(input, plainBuffer, 0, PlainChunkSize, cancellationToken).ConfigureAwait(false);
				endOfStream = bufferFill < PlainChunkSize;

				var tag = endOfStream ? CryptoSecretStreamTag.Final : CryptoSecretStreamTag.Message;

				var written = CryptoSecretStream.EncryptChunk(
					stateBuffer,
					cipherBuffer,
					plainBuffer.AsSpan(0, bufferFill),
					tag
				).Length;

				await output.WriteAsync(cipherBuffer.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
			}
		}
		finally
		{
			SecureMemory.MemZero(stateBuffer);
			SecureMemory.MemZero(plainBuffer);
			TryReturnBuffers(cipherBuffer, plainBuffer);
		}
	}

	/// <summary>
	/// Asynchronously reads data from a stream until the specified number of bytes
	/// have been read or the end of the stream is reached.
	/// </summary>
	/// <param name="stream">The stream to read from.</param>
	/// <param name="buffer">The buffer to fill with data read from the stream.</param>
	/// <param name="offset">The zero-based byte offset in <paramref name="buffer"/> at which to begin
	/// storing the data read from the stream.</param>
	/// <param name="count">The maximum number of bytes to read from the stream.</param>
	/// <param name="ct">A token that can be used to cancel the asynchronous operation.
	/// Defaults to <see cref="CancellationToken.None"/>.</param>
	/// <returns>A <see cref="Task{TResult}"/> that represents the asynchronous read operation.
	/// The result is the total number of bytes read into the buffer. This can be less than
	/// <paramref name="count"/> if the end of the stream is reached before <paramref name="count"/>
	/// bytes are read.</returns>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="stream"/> or <paramref name="buffer"/> is null.</exception>
	/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="offset"/> or <paramref name="count"/>
	/// is negative, or if <paramref name="offset"/> plus <paramref name="count"/> is greater than
	/// the length of <paramref name="buffer"/>.</exception>
	/// <exception cref="OperationCanceledException">Thrown if the operation is canceled via the
	/// <paramref name="ct"/>.</exception>

	private static async Task<int> FillBufferAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
	{
		int totalRead = 0;
		while (totalRead < count)
		{
			int read = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead, ct).ConfigureAwait(false);
			if (read == 0)
				break; // EOF
			totalRead += read;
		}
		return totalRead;
	}

	/// <summary>
	/// Synchronously reads data from a stream until the specified number of bytes
	/// have been read or the end of the stream is reached.
	/// </summary>
	/// <param name="stream">The stream to read from.</param>
	/// <param name="buffer">The buffer to fill with data read from the stream.</param>
	/// <param name="offset">The zero-based byte offset in <paramref name="buffer"/> at which to begin
	/// storing the data read from the stream.</param>
	/// <param name="count">The maximum number of bytes to read from the stream.</param>
	/// <returns>The total number of bytes read into the buffer. This can be less than
	/// <paramref name="count"/> if the end of the stream is reached before <paramref name="count"/>
	/// bytes are read.</returns>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="stream"/> or <paramref name="buffer"/> is null.</exception>
	/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="offset"/> or <paramref name="count"/>
	/// is negative, or if <paramref name="offset"/> plus <paramref name="count"/> is greater than
	/// the length of <paramref name="buffer"/>.</exception>

	private static int FillBuffer(Stream stream, byte[] buffer, int offset, int count)
	{
		int totalRead = 0;
		while (totalRead < count)
		{
			int read = stream.Read(buffer, offset + totalRead, count - totalRead);
			if (read == 0)
				break; // EOF
			totalRead += read;
		}
		return totalRead;
	}

	/// <summary>
	/// Asynchronously encrypts data from the <paramref name="input"/> stream using a key
	/// stored in <see cref="SecureMemory{T}"/> and writes the ciphertext to the <paramref name="output"/> stream.
	/// </summary>
	/// <param name="input">The readable stream containing plaintext to encrypt.</param>
	/// <param name="output">The writable stream where ciphertext will be written.</param>
	/// <param name="key">
	/// A secure memory buffer containing the secret key. It is critical that this buffer is disposed properly
	/// to ensure the key is wiped from memory.
	/// </param>
	/// <param name="cancellationToken">Optional token to cancel the asynchronous operation.</param>
	/// <returns>A task representing the asynchronous encryption process.</returns>
	/// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
	/// <exception cref="ObjectDisposedException">Thrown if the secure key has already been disposed.</exception>
	/// <exception cref="OperationCanceledException">Thrown if the operation is canceled.</exception>
	/// <remarks>
	/// <para>
	/// This overload offers identical functionality to
	/// <see cref="EncryptAsync(Stream, Stream, ReadOnlyMemory{byte}, CancellationToken)"/>,
	/// but uses a <see cref="SecureMemory{T}"/> buffer to enhance key security during runtime.
	/// </para>
	/// <para>
	/// Using secure memory reduces the risk of sensitive data being captured in memory dumps
	/// or accessed by unauthorized code.
	/// </para>
	/// </remarks>
	public static async Task EncryptAsync(
		Stream input,
		Stream output,
		SecureMemory<byte> key,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(key, nameof(key));
		await EncryptAsync(input, output, key.AsMemory(), cancellationToken).ConfigureAwait(false);
	}

	/// <summary>
	/// Attempts to return a rented buffer back to the shared <see cref="ArrayPool{T}"/> instance.
	/// Any exceptions that occur during the return process are caught and ignored to prevent
	/// potential issues during cleanup.
	/// </summary>
	/// <param name="buffer">The buffer to return to the pool. If <paramref name="buffer"/> is null,
	/// this method does nothing.</param>

	private static void TryReturnBuffer(byte[]? buffer)
	{
		try
		{
			if (buffer != null)
				ArrayPool<byte>.Shared.Return(buffer);
		}
		catch
		{
			// Handle any exceptions that may occur during buffer return
			// This is a no-op in this case, but you may want to log the error or take other actions.
		}
	}

	/// <summary>
	/// Attempts to return two rented buffers back to the shared <see cref="ArrayPool{T}"/> instance.
	/// This is a convenience method for returning multiple buffers. Any exceptions that occur
	/// during the return process are caught and ignored.
	/// </summary>
	/// <param name="b1">The first buffer to return to the pool. Can be null.</param>
	/// <param name="b2">The second buffer to return to the pool. Can be null.</param>

	private static void TryReturnBuffers(byte[]? b1, byte[]? b2)
	{
		TryReturnBuffer(b1);
		TryReturnBuffer(b2);
	}

	/// <summary>
	/// Asynchronously decrypts data from the <paramref name="input"/> stream and writes the plaintext
	/// to the <paramref name="output"/> stream, verifying integrity using XChaCha20-Poly1305.
	/// </summary>
	/// <param name="input">
	/// A readable stream containing encrypted data. The stream must begin with the header
	/// produced during encryption.
	/// </param>
	/// <param name="output">The writable stream where decrypted plaintext will be written.</param>
	/// <param name="key">
	/// The secret key used for decryption. It must match the key used during encryption.
	/// </param>
	/// <param name="cancellationToken">Optional token to cancel the asynchronous operation.</param>
	/// <returns>A task representing the asynchronous decryption process.</returns>
	/// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
	/// <exception cref="EndOfStreamException">
	/// Thrown if the stream ends unexpectedly or the final tag is never reached.
	/// </exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if the integrity check fails on any chunk (i.e., authentication tag mismatch).
	/// </exception>
	/// <exception cref="OperationCanceledException">Thrown if the operation is canceled.</exception>
	/// <remarks>
	/// <para>
	/// The decryption process begins by reading the stream header, which includes a nonce required
	/// to initialize the decryption state. Each encrypted chunk is then read, authenticated,
	/// and decrypted in order.
	/// </para>
	/// <para>
	/// If any chunk fails authentication, a <see cref="LibSodiumException"/> is thrown and no plaintext
	/// is written for that chunk. If the stream ends before encountering a chunk tagged as
	/// <see cref="CryptoSecretStreamTag.Final"/>, an <see cref="EndOfStreamException"/> is thrown.
	/// </para>
	/// <para>
	/// This method uses pooled buffers and zeroes out internal state after use to reduce memory leakage risks.
	/// Input and output streams are not closed automatically.
	/// </para>
	/// </remarks>
	public static async Task DecryptAsync(
		Stream input,
		Stream output,
		ReadOnlyMemory<byte> key,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(input, nameof(input));
		ArgumentNullException.ThrowIfNull(output, nameof(output));
		ArgumentNullException.ThrowIfNull(key, nameof(key));
		byte[]? cipherBuffer = null;
		byte[]? plainBuffer = null;
		try
		{
			cipherBuffer = ArrayPool<byte>.Shared.Rent(CipherChunkSize);
			plainBuffer = ArrayPool<byte>.Shared.Rent(PlainChunkSize);
		}
		catch
		{
			TryReturnBuffers(cipherBuffer, plainBuffer);
			throw;
		}

		byte[] stateBuffer = new byte[CryptoSecretStream.StateLen];
		byte[] headerBuffer = new byte[CryptoSecretStream.HeaderLen];

		try
		{
			// Read header
			await input.ReadExactlyAsync(headerBuffer).ConfigureAwait(false);

			CryptoSecretStream.InitializeDecryption(stateBuffer, headerBuffer, key.Span);
			bool tagFinalReached = false;

			while (true)
			{
				int chunkLength = await FillBufferAsync(input, cipherBuffer, 0, CipherChunkSize, cancellationToken).ConfigureAwait(false);
				if (chunkLength == 0)
				{
					if (!tagFinalReached)
					{
						throw new EndOfStreamException("Incomplete stream: Final tag not reached.");
					}
					break;
				}

				CryptoSecretStreamTag tag;
				var plainLen = CryptoSecretStream.DecryptChunk(
					stateBuffer,
					plainBuffer,
					out tag,
					cipherBuffer.AsSpan(0, chunkLength)
				).Length;

				await output.WriteAsync(plainBuffer.AsMemory(0, plainLen), cancellationToken).ConfigureAwait(false);

				if (tag == CryptoSecretStreamTag.Final)
				{
					tagFinalReached = true;
					break;
				}
			}
		}
		finally
		{
			SecureMemory.MemZero(stateBuffer);
			SecureMemory.MemZero(plainBuffer);
			TryReturnBuffers(cipherBuffer, plainBuffer);
		}
	}

	/// <summary>
	/// Asynchronously decrypts data from the <paramref name="input"/> stream using a key
	/// stored in <see cref="SecureMemory{T}"/>, and writes the plaintext to the <paramref name="output"/> stream.
	/// </summary>
	/// <param name="input">
	/// A readable stream containing the encrypted data. The stream must begin with the encryption header.
	/// </param>
	/// <param name="output">The writable stream where the decrypted plaintext will be written.</param>
	/// <param name="key">
	/// A secure memory buffer containing the decryption key. This must match the key used to encrypt the stream.
	/// </param>
	/// <param name="cancellationToken">Optional token to cancel the asynchronous operation.</param>
	/// <returns>A task representing the asynchronous decryption process.</returns>
	/// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
	/// <exception cref="ObjectDisposedException">Thrown if the secure key has already been disposed.</exception>
	/// <exception cref="EndOfStreamException">Thrown if the stream ends before the final tag is reached.</exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if the integrity check fails (e.g., if the ciphertext has been tampered with).
	/// </exception>
	/// <exception cref="OperationCanceledException">Thrown if the operation is canceled.</exception>
	/// <remarks>
	/// <para>
	/// This overload behaves identically to
	/// <see cref="DecryptAsync(Stream, Stream, ReadOnlyMemory{byte}, CancellationToken)"/>,
	/// but uses a <see cref="SecureMemory{T}"/> buffer for enhanced runtime key protection.
	/// </para>
	/// <para>
	/// The key is securely wiped from memory once decryption is complete. Stream lifetime is not managed automatically.
	/// </para>
	/// </remarks>

	public static async Task DecryptAsync(
		Stream input,
		Stream output,
		SecureMemory<byte> key,
		CancellationToken cancellationToken = default)
	{
		await DecryptAsync(input, output, key.AsMemory(), cancellationToken).ConfigureAwait(false);
	}

	/// <summary>
	/// Synchronously encrypts data from the <paramref name="input"/> stream and writes the ciphertext
	/// to the <paramref name="output"/> stream using the XChaCha20-Poly1305 algorithm.
	/// </summary>
	/// <param name="input">The readable stream containing plaintext to encrypt.</param>
	/// <param name="output">The writable stream where ciphertext will be written.</param>
	/// <param name="key">
	/// The encryption key. Must be securely generated and exactly 32 bytes long for XChaCha20-Poly1305.
	/// </param>
	/// <exception cref="ArgumentException">Thrown if the key is invalid.</exception>
	/// <exception cref="EndOfStreamException">Thrown if the input stream ends unexpectedly.</exception>
	/// <remarks>
	/// <para>
	/// This method performs stream encryption in-place and blocks the calling thread until completion.
	/// It is suitable for scenarios where asynchronous patterns are not required or not supported.
	/// </para>
	/// <para>
	/// The input is processed in chunks of <see cref="PlainChunkSize"/> bytes. Each chunk is encrypted
	/// and authenticated before being written to the output stream. A cryptographic header is written at the beginning,
	/// and a final tag is written after the last chunk.
	/// </para>
	/// <para>
	/// All internal buffers are zeroed after use, and pooled memory is returned. The input and output
	/// streams are not closed or disposed automatically.
	/// </para>
	/// </remarks>


	public static void Encrypt(Stream input, Stream output, ReadOnlySpan<byte> key)
	{
		ArgumentNullException.ThrowIfNull(input, nameof(input));
		ArgumentNullException.ThrowIfNull(output, nameof(output));
		byte[]? cipherBuffer = null;
		byte[]? plainBuffer = null;
		try
		{
			cipherBuffer = ArrayPool<byte>.Shared.Rent(CipherChunkSize);
			plainBuffer = ArrayPool<byte>.Shared.Rent(PlainChunkSize);
		}
		catch
		{
			TryReturnBuffers(cipherBuffer, plainBuffer);
			throw;
		}

		Span<byte> stateBuffer = stackalloc byte[CryptoSecretStream.StateLen];
		Span<byte> headerBuffer = stackalloc byte[CryptoSecretStream.HeaderLen];

		try
		{
			CryptoSecretStream.InitializeEncryption(stateBuffer, headerBuffer, key);
			output.Write(headerBuffer);

			int bytesRead = 0;
			bool endOfStream = false;

			while (!endOfStream)
			{
				bytesRead = FillBuffer(input, plainBuffer, 0, PlainChunkSize);
				endOfStream = bytesRead < PlainChunkSize;

				var tag = endOfStream ? CryptoSecretStreamTag.Final : CryptoSecretStreamTag.Message;

				var ciphertext = CryptoSecretStream.EncryptChunk(
					stateBuffer,
					cipherBuffer,
					plainBuffer.AsSpan(0, bytesRead),
					tag
				);

				output.Write(ciphertext);

			}
		}
		finally
		{
			SecureMemory.MemZero(stateBuffer);
			SecureMemory.MemZero(plainBuffer);
			TryReturnBuffers(cipherBuffer, plainBuffer);
		}
	}

	/// <summary>
	/// Synchronously encrypts data from the <paramref name="input"/> stream using a secure key,
	/// and writes the ciphertext to the <paramref name="output"/> stream.
	/// </summary>
	/// <param name="input">The readable stream containing plaintext to encrypt.</param>
	/// <param name="output">The writable stream where ciphertext will be written.</param>
	/// <param name="key">
	/// A <see cref="SecureMemory{T}"/> buffer containing the encryption key. It must be 32 bytes in size,
	/// and will be securely wiped from memory after use.
	/// </param>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/>, <paramref name="input"/>, or <paramref name="output"/> is null.</exception>
	/// <exception cref="ObjectDisposedException">Thrown if the key has already been disposed.</exception>
	/// <exception cref="ArgumentException">Thrown if the key is invalid (wrong length).</exception>
	/// <remarks>
	/// <para>
	/// This method is functionally equivalent to <see cref="Encrypt(Stream, Stream, ReadOnlySpan{byte})"/>,
	/// but accepts the encryption key wrapped in <see cref="SecureMemory{T}"/> for added in-memory protection.
	/// </para>
	/// <para>
	/// This improves resistance to key leakage through memory inspection, especially in long-lived processes.
	/// </para>
	/// </remarks>
	public static void Encrypt(Stream input, Stream output, SecureMemory<byte> key)
	{
		Encrypt(input, output, key.AsSpan());
	}

	/// <summary>
	/// Synchronously decrypts data from the <paramref name="input"/> stream and writes the plaintext
	/// to the <paramref name="output"/> stream, verifying each chunk's authenticity using XChaCha20-Poly1305.
	/// </summary>
	/// <param name="input">
	/// The readable stream containing encrypted data. The stream must begin with the encryption header
	/// produced during the corresponding encryption process.
	/// </param>
	/// <param name="output">The writable stream where decrypted plaintext will be written.</param>
	/// <param name="key">
	/// The secret decryption key. It must match the key used to encrypt the stream and be exactly 32 bytes long.
	/// </param>
	/// <exception cref="ArgumentException">Thrown if the key is invalid.</exception>
	/// <exception cref="EndOfStreamException">
	/// Thrown if the stream ends before the <see cref="CryptoSecretStreamTag.Final"/> tag is reached,
	/// indicating an incomplete or truncated stream.
	/// </exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if authentication fails, indicating the ciphertext has been tampered with or the wrong key was used.
	/// </exception>
	/// <remarks>
	/// <para>
	/// This method processes the encrypted stream in chunks, validating each chunk before decrypting it.
	/// If authentication fails, a <see cref="LibSodiumException"/> is thrown and the decrypted output is invalidated.
	/// </para>
	/// <para>
	/// The stream must start with a header containing the nonce and metadata necessary for decryption.
	/// This header is automatically consumed at the beginning of the stream.
	/// </para>
	/// <para>
	/// All internal buffers are zeroed after use. The input and output streams are not closed automatically.
	/// </para>
	/// </remarks>

	public static void Decrypt(Stream input, Stream output, ReadOnlySpan<byte> key)
	{
		byte[]? cipherBuffer = null;
		byte[]? plainBuffer = null;
		try
		{
			cipherBuffer = ArrayPool<byte>.Shared.Rent(CipherChunkSize);
			plainBuffer = ArrayPool<byte>.Shared.Rent(PlainChunkSize);
		}
		catch
		{
			TryReturnBuffers(cipherBuffer, plainBuffer);
			throw;
		}

		Span<byte> stateBuffer = stackalloc byte[CryptoSecretStream.StateLen];
		Span<byte> headerBuffer = stackalloc byte[CryptoSecretStream.HeaderLen];

		try
		{
			input.ReadExactly(headerBuffer);

			CryptoSecretStream.InitializeDecryption(stateBuffer, headerBuffer, key);

			bool tagFinalReached = false;

			while (true)
			{
				int chunkLength = FillBuffer(input, cipherBuffer, 0, CipherChunkSize);
				if (chunkLength == 0)
				{
					if (!tagFinalReached)
						throw new EndOfStreamException("Incomplete stream: Final tag was not reached.");
					break;
				}

				CryptoSecretStreamTag tag;
				var clearSpan = CryptoSecretStream.DecryptChunk(
					stateBuffer,
					plainBuffer,
					out tag,
					cipherBuffer.AsSpan(0, chunkLength)
				);

				output.Write(clearSpan);

				if (tag == CryptoSecretStreamTag.Final)
				{
					tagFinalReached = true;
					break;
				}
			}
		}
		finally
		{
			SecureMemory.MemZero(stateBuffer);
			SecureMemory.MemZero(plainBuffer);
			TryReturnBuffers(cipherBuffer, plainBuffer);
		}
	}

	/// <summary>
	/// Synchronously decrypts data from the <paramref name="input"/> stream using a key stored in secure memory,
	/// and writes the plaintext to the <paramref name="output"/> stream.
	/// </summary>
	/// <param name="input">
	/// The stream containing encrypted data. It must begin with the secret stream header written during encryption.
	/// </param>
	/// <param name="output">The stream where decrypted plaintext will be written.</param>
	/// <param name="key">
	/// A <see cref="SecureMemory{T}"/> buffer containing the decryption key. This key must match the one used to encrypt the stream.
	/// </param>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/>, <paramref name="output"/>, or <paramref name="key"/> is null.</exception>
	/// <exception cref="ObjectDisposedException">Thrown if the secure memory key has already been disposed.</exception>
	/// <exception cref="EndOfStreamException">Thrown if the stream ends before the <see cref="CryptoSecretStreamTag.Final"/> tag is encountered.</exception>
	/// <exception cref="LibSodiumException">
	/// Thrown if the authentication of a chunk fails, which indicates tampering or a mismatched key.
	/// </exception>
	/// <remarks>
	/// <para>
	/// This method behaves identically to <see cref="Decrypt(Stream, Stream, ReadOnlySpan{byte})"/>,
	/// but uses a secure memory buffer for enhanced key confidentiality.
	/// </para>
	/// <para>
	/// The decryption header is consumed automatically at the beginning of the stream. Chunks are processed sequentially,
	/// and any failure in tag verification will cause decryption to halt with an exception.
	/// </para>
	/// <para>
	/// Internal buffers are cleared and returned to the pool after use. The input and output streams remain open.
	/// </para>
	/// </remarks>


	public static void Decrypt(Stream input, Stream output, SecureMemory<byte> key)
	{
		Decrypt(input, output, key.AsReadOnlySpan());
	}
}
