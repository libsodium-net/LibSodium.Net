using LibSodium.Interop;

namespace LibSodium;

/// <summary>
/// Constants and cryptographic operations for the Ristretto255 group.
/// </summary>
/// <remarks>
/// 🧂 Based on libsodium’s Ristretto255 API: https://doc.libsodium.org/advanced/ristretto255
/// </remarks>
public static class CryptoRistretto
{
	/// <summary>
	/// Length of a Ristretto255 encoded point in bytes (32).
	/// </summary>
	public const int PointLen = 32;

	/// <summary>
	/// Length of a hash input required for point derivation in bytes (64).
	/// </summary>
	public const int HashLen = 64;

	/// <summary>
	/// Length of a Ristretto255 scalar in bytes (32).
	/// </summary>
	public const int ScalarLen = 32;

	/// <summary>
	/// Length of a non-reduced scalar input in bytes (64).
	/// </summary>
	public const int NonReducedScalarLen = 64;

	/// <summary>
	/// Checks whether the given 32-byte buffer is a valid Ristretto255 encoded point.
	/// </summary>
	/// <param name="point">The encoded point to validate. Must be exactly 32 bytes.</param>
	/// <returns><c>true</c> if the point is valid; otherwise, <c>false</c>.</returns>
	/// <exception cref="ArgumentException">Thrown if <paramref name="point"/> is not exactly 32 bytes.</exception>
	public static bool IsValidPoint(ReadOnlySpan<byte> point)
	{
		if (point.Length != PointLen)
			throw new ArgumentException($"Point must be exactly {PointLen} bytes.", nameof(point));

		return Native.crypto_core_ristretto255_is_valid_point(point) == 1;
	}

	/// <summary>
	/// Generates a uniformly random valid Ristretto255 point.
	/// </summary>
	/// <param name="point">The buffer to receive the generated point. Must be exactly 32 bytes.</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="point"/> is not exactly 32 bytes.</exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void GenerateRandomPoint(Span<byte> point)
	{
		if (point.Length != PointLen)
			throw new ArgumentException($"Point must be exactly {PointLen} bytes.", nameof(point));

		int rc = Native.crypto_core_ristretto255_random(point);
		if (rc != 0)
			throw new LibSodiumException("Failed to generate random Ristretto255 point.");
	}

	/// <summary>
	/// Derives a Ristretto255 point from a 64-byte uniformly random hash input.
	/// </summary>
	/// <param name="hash">A 64-byte uniformly random input.</param>
	/// <param name="point">The buffer to receive the resulting point. Must be exactly 32 bytes.</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="point"/> is not 32 bytes or <paramref name="hash"/> is not 64 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void DerivePointFromHash(ReadOnlySpan<byte> hash, Span<byte> point)
	{
		if (hash.Length != HashLen)
			throw new ArgumentException($"Hash must be exactly {HashLen} bytes.", nameof(hash));
		if (point.Length != PointLen)
			throw new ArgumentException($"Point must be exactly {PointLen} bytes.", nameof(point));

		int rc = Native.crypto_core_ristretto255_from_hash(point, hash);
		if (rc != 0)
			throw new LibSodiumException("Failed to derive Ristretto255 point from hash.");
	}

	/// <summary>
	/// Derives a Ristretto255 point from a 64-byte uniformly random hash input.
	/// </summary>
	/// <param name="hash">A 64-byte uniformly random input.</param>
	/// <param name="point">The buffer to receive the resulting point. Must be exactly 32 bytes.</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="point"/> is not 32 bytes or <paramref name="hash"/> is not 64 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void DerivePointFromHash(SecureMemory<byte> hash, SecureMemory<byte> point)
	{
		DerivePointFromHash(hash.AsReadOnlySpan(), point.AsSpan());
	}

	/// <summary>
	/// Computes the scalar multiplication of a Ristretto255 point by a scalar: <c>resultPoint = scalar * point</c>.
	/// </summary>
	/// <param name="scalar">The scalar to multiply (32 bytes).</param>
	/// <param name="point">The Ristretto255 point to multiply (32 bytes).</param>
	/// <param name="resultPoint">The buffer to receive the resulting point (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="scalar"/>, <paramref name="point"/>, or <paramref name="resultPoint"/> do not have the correct length.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void ScalarMultiply(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> point, Span<byte> resultPoint)
	{
		if (scalar.Length != ScalarLen)
			throw new ArgumentException($"Scalar must be exactly {ScalarLen} bytes.", nameof(scalar));
		if (point.Length != PointLen)
			throw new ArgumentException($"Point must be exactly {PointLen} bytes.", nameof(point));
		if (resultPoint.Length != PointLen)
			throw new ArgumentException($"Result point must be exactly {PointLen} bytes.", nameof(resultPoint));

		int rc = Native.crypto_scalarmult_ristretto255(resultPoint, scalar, point);
		if (rc != 0)
			throw new LibSodiumException("Scalar multiplication failed.");
	}

	/// <summary>
	/// Computes the scalar multiplication of a Ristretto255 point by a scalar: <c>resultPoint = scalar * point</c>.
	/// </summary>
	/// <param name="scalar">The scalar to multiply (32 bytes).</param>
	/// <param name="point">The Ristretto255 point to multiply (32 bytes).</param>
	/// <param name="resultPoint">The buffer to receive the resulting point (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="scalar"/>, <paramref name="point"/>, or <paramref name="resultPoint"/> do not have the correct length.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void ScalarMultiply(SecureMemory<byte> scalar, SecureMemory<byte> point, SecureMemory<byte> resultPoint)
	{
		ScalarMultiply(scalar.AsReadOnlySpan(), point.AsReadOnlySpan(), resultPoint.AsSpan());
	}

	/// <summary>
	/// Computes the scalar multiplication of a Ristretto255 point by a scalar: <c>resultPoint = scalar * point</c>.
	/// </summary>
	/// <param name="scalar">The scalar to multiply (32 bytes).</param>
	/// <param name="point">The Ristretto255 point to multiply (32 bytes).</param>
	/// <param name="resultPoint">The buffer to receive the resulting point (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="scalar"/>, <paramref name="point"/>, or <paramref name="resultPoint"/> do not have the correct length.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void ScalarMultiply(SecureMemory<byte> scalar, ReadOnlySpan<byte> point, SecureMemory<byte> resultPoint)
	{
		ScalarMultiply(scalar.AsReadOnlySpan(), point, resultPoint.AsSpan());
	}

	/// <summary>
	/// Computes the scalar multiplication of the Ristretto255 base point by a scalar: <c>resultPoint = scalar * base_point</c>.
	/// Typically used to derive a public key from a private scalar.
	/// </summary>
	/// <param name="scalar">The scalar to multiply (32 bytes). This is typically a private key.</param>
	/// <param name="resultPoint">The buffer to receive the resulting point (32 bytes). This is typically the corresponding public key.</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="scalar"/> or <paramref name="resultPoint"/> do not have the correct length.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void ScalarMultiplyBase(ReadOnlySpan<byte> scalar, Span<byte> resultPoint)
	{
		if (scalar.Length != ScalarLen)
			throw new ArgumentException($"Scalar must be exactly {ScalarLen} bytes.", nameof(scalar));
		if (resultPoint.Length != PointLen)
			throw new ArgumentException($"Result point must be exactly {PointLen} bytes.", nameof(resultPoint));

		int rc = Native.crypto_scalarmult_ristretto255_base(resultPoint, scalar);
		if (rc != 0)
			throw new LibSodiumException("Scalar multiplication with base point failed.");
	}

	/// <summary>
	/// Computes the scalar multiplication of the Ristretto255 base point by a scalar: <c>resultPoint = scalar * base_point</c>.
	/// Typically used to derive a public key from a private scalar.
	/// </summary>
	/// <param name="scalar">The private scalar (32 bytes).</param>
	/// <param name="resultPoint">The buffer to receive the resulting point (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="scalar"/> or <paramref name="resultPoint"/> do not have the correct length.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void ScalarMultiplyBase(SecureMemory<byte> scalar, Span<byte> resultPoint)
	{
		ScalarMultiplyBase(scalar.AsSpan(), resultPoint);
	}

	/// <summary>
	/// Adds two Ristretto255 points: <c>resultPoint = point1 + point2</c>.
	/// </summary>
	/// <param name="point1">The first input point (32 bytes).</param>
	/// <param name="point2">The second input point (32 bytes).</param>
	/// <param name="resultPoint">The buffer to receive the result (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if any buffer is not exactly 32 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void AddPoints(ReadOnlySpan<byte> point1, ReadOnlySpan<byte> point2, Span<byte> resultPoint)
	{
		if (point1.Length != PointLen)
			throw new ArgumentException($"Point1 must be exactly {PointLen} bytes.", nameof(point1));
		if (point2.Length != PointLen)
			throw new ArgumentException($"Point2 must be exactly {PointLen} bytes.", nameof(point2));
		if (resultPoint.Length != PointLen)
			throw new ArgumentException($"Result point must be exactly {PointLen} bytes.", nameof(resultPoint));

		int rc = Native.crypto_core_ristretto255_add(resultPoint, point1, point2);
		if (rc != 0)
			throw new LibSodiumException("Point addition failed.");
	}

	/// <summary>
	/// Subtracts one Ristretto255 point from another: <c>resultPoint = point1 - point2</c>.
	/// </summary>
	/// <param name="point1">The point to subtract from (32 bytes).</param>
	/// <param name="point2">The point to subtract (32 bytes).</param>
	/// <param name="resultPoint">The buffer to receive the result (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if any buffer is not exactly 32 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void SubtractPoints(ReadOnlySpan<byte> point1, ReadOnlySpan<byte> point2, Span<byte> resultPoint)
	{
		if (point1.Length != PointLen)
			throw new ArgumentException($"Point1 must be exactly {PointLen} bytes.", nameof(point1));
		if (point2.Length != PointLen)
			throw new ArgumentException($"Point2 must be exactly {PointLen} bytes.", nameof(point2));
		if (resultPoint.Length != PointLen)
			throw new ArgumentException($"Result point must be exactly {PointLen} bytes.", nameof(resultPoint));

		int rc = Native.crypto_core_ristretto255_sub(resultPoint, point1, point2);
		if (rc != 0)
			throw new LibSodiumException("Point subtraction failed.");
	}

	/// <summary>
	/// Generates a uniformly random scalar modulo the Ristretto255 group order (32 bytes).
	/// This is typically used to generate a random private key.
	/// </summary>
	/// <param name="resultScalar">The buffer to receive the scalar (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="resultScalar"/> is not exactly 32 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void GenerateRandomScalar(Span<byte> resultScalar)
	{
		if (resultScalar.Length != ScalarLen)
			throw new ArgumentException($"Result scalar must be exactly {ScalarLen} bytes.", nameof(resultScalar));

		int rc = Native.crypto_core_ristretto255_scalar_random(resultScalar);
		if (rc != 0)
			throw new LibSodiumException("Scalar generation failed.");
	}

	/// <summary>
	/// Generates a uniformly random scalar modulo the Ristretto255 group order (32 bytes).
	/// This is typically used to generate a random private key.
	/// </summary>
	/// <param name="resultScalar">The buffer to receive the scalar (32 bytes, secret).</param>
	/// <exception cref="ArgumentException">Thrown if <paramref name="resultScalar"/> is not 32 bytes.</exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void GenerateRandomScalar(SecureMemory<byte> resultScalar)
	{
		GenerateRandomScalar(resultScalar.AsSpan());
	}


	/// <summary>
	/// Reduces a 64-byte non-reduced scalar to a canonical 32-byte scalar modulo the Ristretto255 group order.
	/// This is typically used after hashing to produce a valid private key.
	/// </summary>
	/// <param name="nonReducedScalar">The 64-byte input scalar to reduce.</param>
	/// <param name="resultScalar">The buffer to receive the reduced scalar (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="nonReducedScalar"/> is not 64 bytes or <paramref name="resultScalar"/> is not 32 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void ReduceScalar(ReadOnlySpan<byte> nonReducedScalar, Span<byte> resultScalar)
	{
		if (nonReducedScalar.Length != NonReducedScalarLen)
			throw new ArgumentException($"Input scalar must be exactly {NonReducedScalarLen} bytes.", nameof(nonReducedScalar));
		if (resultScalar.Length != ScalarLen)
			throw new ArgumentException($"Result scalar must be exactly {ScalarLen} bytes.", nameof(resultScalar));

		int rc = Native.crypto_core_ristretto255_scalar_reduce(resultScalar, nonReducedScalar);
		if (rc != 0)
			throw new LibSodiumException("Scalar reduction failed.");
	}

	/// <summary>
	/// Reduces a 64-byte non-reduced scalar to a canonical 32-byte scalar modulo the Ristretto255 group order.
	/// This is typically used after hashing or key derivation to produce a valid private key.
	/// </summary>
	/// <param name="nonReducedScalar">The 64-byte input scalar to reduce (typically secret).</param>
	/// <param name="resultScalar">The buffer to receive the reduced scalar (also secret, 32 bytes).</param>
	/// <exception cref="ArgumentException">Thrown if the input or output buffers have incorrect length.</exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally.</exception>
	public static void ReduceScalar(SecureMemory<byte> nonReducedScalar, SecureMemory<byte> resultScalar)
	{
		ReduceScalar(nonReducedScalar.AsReadOnlySpan(), resultScalar.AsSpan());
	}


	/// <summary>
	/// Computes the multiplicative inverse of a scalar modulo the Ristretto255 group order: <c>resultScalar = inverse(inputScalar)</c>.
	/// </summary>
	/// <param name="inputScalar">The scalar to invert (32 bytes).</param>
	/// <param name="resultScalar">The buffer to receive the inverted scalar (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="inputScalar"/> or <paramref name="resultScalar"/> is not exactly 32 bytes.
	/// </exception>
	/// <exception cref="LibSodiumException">Thrown if the operation fails internally or the scalar is not invertible.</exception>
	public static void InvertScalar(ReadOnlySpan<byte> inputScalar, Span<byte> resultScalar)
	{
		if (inputScalar.Length != ScalarLen)
			throw new ArgumentException($"Input scalar must be exactly {ScalarLen} bytes.", nameof(inputScalar));
		if (resultScalar.Length != ScalarLen)
			throw new ArgumentException($"Result scalar must be exactly {ScalarLen} bytes.", nameof(resultScalar));

		int rc = Native.crypto_core_ristretto255_scalar_invert(resultScalar, inputScalar);
		if (rc != 0)
			throw new LibSodiumException("Scalar inversion failed.");
	}

	/// <summary>
	/// Computes the additive inverse of a scalar modulo the Ristretto255 group order: <c>resultScalar = -inputScalar</c>.
	/// </summary>
	/// <param name="inputScalar">The scalar to negate (32 bytes).</param>
	/// <param name="resultScalar">The buffer to receive the negated scalar (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="inputScalar"/> or <paramref name="resultScalar"/> is not exactly 32 bytes.
	/// </exception>
	public static void NegateScalar(ReadOnlySpan<byte> inputScalar, Span<byte> resultScalar)
	{
		if (inputScalar.Length != ScalarLen)
			throw new ArgumentException($"Input scalar must be exactly {ScalarLen} bytes.", nameof(inputScalar));
		if (resultScalar.Length != ScalarLen)
			throw new ArgumentException($"Result scalar must be exactly {ScalarLen} bytes.", nameof(resultScalar));

		Native.crypto_core_ristretto255_scalar_negate(resultScalar, inputScalar);
	}

	/// <summary>
	/// Computes the additive inverse of a scalar modulo the Ristretto255 group order: <c>resultScalar = -inputScalar</c>.
	/// </summary>
	/// <param name="inputScalar">The scalar to negate (32 bytes).</param>
	/// <param name="resultScalar">The buffer to receive the negated scalar (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="inputScalar"/> or <paramref name="resultScalar"/> is not exactly 32 bytes.
	/// </exception>
	public static void NegateScalar(SecureMemory<byte> inputScalar, SecureMemory<byte> resultScalar)
	{
		NegateScalar(inputScalar.AsReadOnlySpan(), resultScalar.AsSpan());
	}

	/// <summary>
	/// Computes the complement of a scalar modulo the Ristretto255 group order: <c>resultScalar = l - inputScalar</c>.
	/// </summary>
	/// <param name="inputScalar">The scalar to complement (32 bytes).</param>
	/// <param name="resultScalar">The buffer to receive the complemented scalar (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if <paramref name="inputScalar"/> or <paramref name="resultScalar"/> is not exactly 32 bytes.
	/// </exception>
	public static void ComplementScalar(ReadOnlySpan<byte> inputScalar, Span<byte> resultScalar)
	{
		if (inputScalar.Length != ScalarLen)
			throw new ArgumentException($"Input scalar must be exactly {ScalarLen} bytes.", nameof(inputScalar));
		if (resultScalar.Length != ScalarLen)
			throw new ArgumentException($"Result scalar must be exactly {ScalarLen} bytes.", nameof(resultScalar));

		Native.crypto_core_ristretto255_scalar_complement(resultScalar, inputScalar);
	}

	/// <summary>
	/// Adds two scalars modulo the Ristretto255 group order: <c>resultScalar = scalar1 + scalar2</c>.
	/// </summary>
	/// <param name="scalar1">The first scalar operand (32 bytes).</param>
	/// <param name="scalar2">The second scalar operand (32 bytes).</param>
	/// <param name="resultScalar">The buffer to receive the sum (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if any of the buffers are not exactly 32 bytes.
	/// </exception>
	public static void AddScalars(ReadOnlySpan<byte> scalar1, ReadOnlySpan<byte> scalar2, Span<byte> resultScalar)
	{
		if (scalar1.Length != ScalarLen)
			throw new ArgumentException($"Scalar1 must be exactly {ScalarLen} bytes.", nameof(scalar1));
		if (scalar2.Length != ScalarLen)
			throw new ArgumentException($"Scalar2 must be exactly {ScalarLen} bytes.", nameof(scalar2));
		if (resultScalar.Length != ScalarLen)
			throw new ArgumentException($"Result scalar must be exactly {ScalarLen} bytes.", nameof(resultScalar));

		Native.crypto_core_ristretto255_scalar_add(resultScalar, scalar1, scalar2);
	}

	/// <summary>
	/// Subtracts one scalar from another modulo the Ristretto255 group order: <c>resultScalar = scalar1 - scalar2</c>.
	/// </summary>
	/// <param name="scalar1">The scalar to subtract from (32 bytes).</param>
	/// <param name="scalar2">The scalar to subtract (32 bytes).</param>
	/// <param name="resultScalar">The buffer to receive the result (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if any of the buffers are not exactly 32 bytes.
	/// </exception>
	public static void SubtractScalars(ReadOnlySpan<byte> scalar1, ReadOnlySpan<byte> scalar2, Span<byte> resultScalar)
	{
		if (scalar1.Length != ScalarLen)
			throw new ArgumentException($"Scalar1 must be exactly {ScalarLen} bytes.", nameof(scalar1));
		if (scalar2.Length != ScalarLen)
			throw new ArgumentException($"Scalar2 must be exactly {ScalarLen} bytes.", nameof(scalar2));
		if (resultScalar.Length != ScalarLen)
			throw new ArgumentException($"Result scalar must be exactly {ScalarLen} bytes.", nameof(resultScalar));

		Native.crypto_core_ristretto255_scalar_sub(resultScalar, scalar1, scalar2);
	}


	/// <summary>
	/// Multiplies two scalars modulo the Ristretto255 group order: <c>resultScalar = scalar1 × scalar2</c>.
	/// </summary>
	/// <param name="scalar1">The first scalar operand (32 bytes).</param>
	/// <param name="scalar2">The second scalar operand (32 bytes).</param>
	/// <param name="resultScalar">The buffer to receive the product (32 bytes).</param>
	/// <exception cref="ArgumentException">
	/// Thrown if any of the buffers are not exactly 32 bytes.
	/// </exception>
	public static void MultiplyScalars(ReadOnlySpan<byte> scalar1, ReadOnlySpan<byte> scalar2, Span<byte> resultScalar)
	{
		if (scalar1.Length != ScalarLen)
			throw new ArgumentException($"Scalar1 must be exactly {ScalarLen} bytes.", nameof(scalar1));
		if (scalar2.Length != ScalarLen)
			throw new ArgumentException($"Scalar2 must be exactly {ScalarLen} bytes.", nameof(scalar2));
		if (resultScalar.Length != ScalarLen)
			throw new ArgumentException($"Result scalar must be exactly {ScalarLen} bytes.", nameof(resultScalar));

		Native.crypto_core_ristretto255_scalar_mul(resultScalar, scalar1, scalar2);
	}
}
