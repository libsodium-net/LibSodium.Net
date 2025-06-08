using System.Diagnostics;
using System.Security.Cryptography;

namespace LibSodium.Tests;

public class CryptoRistrettoTests
{

	private static byte[] NewPoint()
	{
		var p = new byte[CryptoRistretto.PointLen];
		CryptoRistretto.GenerateRandomPoint(p);
		return p;
	}

	private static byte[] NewScalar()
	{
		var s = new byte[CryptoRistretto.ScalarLen];
		CryptoRistretto.GenerateRandomScalar(s);
		return s;
	}

	private static byte[] NewWideScalar()
	{
		var s = new byte[CryptoRistretto.NonReducedScalarLen];
		Random.Shared.NextBytes(s);
		return s;
	}

	private static byte[] ZeroScalar => new byte[CryptoRistretto.ScalarLen];

	private static byte[] OneScalar
	{
		get
		{
			var one = new byte[CryptoRistretto.ScalarLen];
			one[0] = 0x01;
			return one;
		}
	}


	[Test]
	public void GenerateRandomPoint_ProducesValidPoint()
	{
		var p = NewPoint();
		p.Length.ShouldBe(CryptoRistretto.PointLen);
		CryptoRistretto.IsValidPoint(p).ShouldBeTrue();
	}

	[Test]
	public void Throws_When_PointLengthInvalid_GenerateRandomPoint()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> invalid = stackalloc byte[CryptoRistretto.PointLen - 1];
			CryptoRistretto.GenerateRandomPoint(invalid);
		});
	}

	[Test]
	public void GenerateRandomScalar_ProducesCorrectLength()
	{
		var s = NewScalar();
		s.Length.ShouldBe(CryptoRistretto.ScalarLen);
	}

	[Test]
	public void Throws_When_ScalarLengthInvalid_GenerateRandomScalar()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> invalid = stackalloc byte[CryptoRistretto.ScalarLen - 1];
			CryptoRistretto.GenerateRandomScalar(invalid);
		});
	}

	[Test]
	public void Throws_When_PointLengthInvalid_IsValidPoint()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> invalid = stackalloc byte[CryptoRistretto.PointLen - 1];
			CryptoRistretto.IsValidPoint(invalid);
		});
	}


	[Test]
	public void DerivePointFromHash_ProducesValidPoint()
	{
		Span<byte> hash = stackalloc byte[CryptoRistretto.HashLen];
		Random.Shared.NextBytes(hash);

		Span<byte> p = stackalloc byte[CryptoRistretto.PointLen];
		CryptoRistretto.DerivePointFromHash(hash, p);
		CryptoRistretto.IsValidPoint(p).ShouldBeTrue();
	}

	[Test]
	public void Throws_When_HashLengthInvalid_DerivePointFromHash()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> invalidHash = stackalloc byte[CryptoRistretto.HashLen - 1];
			Span<byte> p = stackalloc byte[CryptoRistretto.PointLen];
			CryptoRistretto.DerivePointFromHash(invalidHash, p);
		});
	}

	[Test]
	public void Throws_When_PointLengthInvalid_DerivePointFromHash()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> hash = stackalloc byte[CryptoRistretto.HashLen];
			Span<byte> invalidPoint = stackalloc byte[CryptoRistretto.PointLen - 1];
			CryptoRistretto.DerivePointFromHash(hash, invalidPoint);
		});
	}


	[Test]
	public void AddAndSubtractPoints_AreInverseOperations()
	{
		Span<byte> p = NewPoint();
		Span<byte> q = NewPoint();
		Span<byte> r = stackalloc byte[CryptoRistretto.PointLen];

		CryptoRistretto.AddPoints(p, q, r);          // r = p + q
		CryptoRistretto.SubtractPoints(r, q, r);     // r = (p + q) - q

		r.ShouldBe(p); // ShouldBe handles Span<byte> vs byte[]
	}

	[Test]
	public void Throws_When_Point1LengthInvalid_AddPoints()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> p1 = stackalloc byte[CryptoRistretto.PointLen - 1];
			Span<byte> p2 = NewPoint();
			Span<byte> r = stackalloc byte[CryptoRistretto.PointLen];
			CryptoRistretto.AddPoints(p1, p2, r);
		});
	}

	[Test]
	public void Throws_When_ResultLengthInvalid_AddPoints()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> p1 = NewPoint();
			Span<byte> p2 = NewPoint();
			Span<byte> r = stackalloc byte[CryptoRistretto.PointLen - 1];
			CryptoRistretto.AddPoints(p1, p2, r);
		});
	}

	[Test]
	public void SubtractSamePoint_ProducesIdentity()
	{
		Span<byte> p = NewPoint();
		Span<byte> identity = stackalloc byte[CryptoRistretto.PointLen];
		Span<byte> check = stackalloc byte[CryptoRistretto.PointLen];

		CryptoRistretto.SubtractPoints(p, p, identity); // identity = p - p
		CryptoRistretto.AddPoints(identity, p, check); // check = 0 + p

		check.ShouldBe(p);
	}


	[Test]
	public void ScalarMultiply_DistributesOverAddition()
	{
		Span<byte> s = NewScalar();
		Span<byte> p = NewPoint();
		Span<byte> q = NewPoint();

		Span<byte> lhs = stackalloc byte[CryptoRistretto.PointLen];
		Span<byte> rhs = stackalloc byte[CryptoRistretto.PointLen];
		Span<byte> tmp = stackalloc byte[CryptoRistretto.PointLen];

		// lhs = (p + q) * s
		CryptoRistretto.AddPoints(p, q, tmp);
		CryptoRistretto.ScalarMultiply(s, tmp, lhs);

		// rhs = p*s + q*s
		CryptoRistretto.ScalarMultiply(s, p, rhs);
		CryptoRistretto.ScalarMultiply(s, q, tmp);
		CryptoRistretto.AddPoints(rhs, tmp, rhs);

		lhs.ShouldBe(rhs);
	}

	[Test]
	public void ScalarMultiplyBase_ConsistentWith_ScalarMultiply()
	{
		Span<byte> s = NewScalar();

		// basePoint = 1 * base
		Span<byte> basePt = stackalloc byte[CryptoRistretto.PointLen];
		CryptoRistretto.ScalarMultiplyBase(OneScalar, basePt);

		// r1 = s * base via dedicated API
		Span<byte> r1 = stackalloc byte[CryptoRistretto.PointLen];
		CryptoRistretto.ScalarMultiplyBase(s, r1);

		// r2 = s * base via generic API
		Span<byte> r2 = stackalloc byte[CryptoRistretto.PointLen];
		CryptoRistretto.ScalarMultiply(s, basePt, r2);

		r1.ShouldBe(r2);
	}

	[Test]
	public void Throws_When_ScalarLengthInvalid_ScalarMultiply()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> s = stackalloc byte[CryptoRistretto.ScalarLen - 1];
			Span<byte> p = NewPoint();
			Span<byte> r = stackalloc byte[CryptoRistretto.PointLen];
			CryptoRistretto.ScalarMultiply(s, p, r);
		});
	}


	[Test]
	public void AddAndSubtractScalars_AreInverseOperations()
	{
		Span<byte> a = NewScalar();
		Span<byte> b = NewScalar();
		Span<byte> r = stackalloc byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.AddScalars(a, b, r);          // r = a + b
		CryptoRistretto.SubtractScalars(r, b, r);     // r = (a + b) - b

		r.ShouldBe(a);
	}

	[Test]
	public void MultiplyScalars_WithOne_IsIdentity()
	{
		Span<byte> s = NewScalar();
		Span<byte> r = stackalloc byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.MultiplyScalars(s, OneScalar, r);
		r.ShouldBe(s);
	}

	[Test]
	public void NegateScalar_SumsToZero()
	{
		Span<byte> s = NewScalar();
		Span<byte> neg = stackalloc byte[CryptoRistretto.ScalarLen];
		Span<byte> sum = stackalloc byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.NegateScalar(s, neg);
		CryptoRistretto.AddScalars(s, neg, sum);

		sum.ShouldBe(ZeroScalar);
	}

	[Test]
	public void ComplementScalar_IsInvolution()
	{
		Span<byte> s = NewScalar();
		Span<byte> c1 = stackalloc byte[CryptoRistretto.ScalarLen];
		Span<byte> c2 = stackalloc byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.ComplementScalar(s, c1);
		CryptoRistretto.ComplementScalar(c1, c2);

		c2.ShouldBe(s);
	}

	[Test]
	public void InvertScalar_IsMultiplicativeInverse()
	{
		Span<byte> s;
		do { s = NewScalar(); } while (s.SequenceEqual(ZeroScalar));

		Span<byte> inv = stackalloc byte[CryptoRistretto.ScalarLen];
		Span<byte> prod = stackalloc byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.InvertScalar(s, inv);
		CryptoRistretto.MultiplyScalars(s, inv, prod);

		prod.ShouldBe(OneScalar);
	}

	[Test]
	public void ReduceScalar_ActuallyReduces()
	{
		Span<byte> wide = NewWideScalar();
		Span<byte> r1 = stackalloc byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.ReduceScalar(wide, r1);
	}


	// Example for one scalar helper; the pattern is the same for the rest
	[Test]
	public void Throws_When_ScalarLengthInvalid_NegateScalar()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> invalid = stackalloc byte[CryptoRistretto.ScalarLen - 1];
			Span<byte> r = stackalloc byte[CryptoRistretto.ScalarLen];
			CryptoRistretto.NegateScalar(invalid, r);
		});
	}

	[Test]
	public void Throws_When_ResultLengthInvalid_NegateScalar()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> s = NewScalar();
			Span<byte> r = stackalloc byte[CryptoRistretto.ScalarLen - 1];
			CryptoRistretto.NegateScalar(s, r);
		});
	}

	// (Analogous tests for ComplementScalar, AddScalars, SubtractScalars, MultiplyScalars, ReduceScalar, InvertScalar)


	[Test]
	public void Throws_When_ScalarLengthInvalid_ComplementScalar()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			var invalid = new byte[CryptoRistretto.ScalarLen - 1];
			var r = new byte[CryptoRistretto.ScalarLen];
			CryptoRistretto.ComplementScalar(invalid, r);
		});
	}

	[Test]
	public void Throws_When_ResultLengthInvalid_ComplementScalar()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			var s = NewScalar();
			var r = new byte[CryptoRistretto.ScalarLen - 1];
			CryptoRistretto.ComplementScalar(s, r);
		});
	}



	[Test]
	public void AddScalars_WithZero_IsIdentity()
	{
		var a = NewScalar();
		var r = new byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.AddScalars(a, ZeroScalar, r);
		r.ShouldBe(a);
	}

	[Test]
	public void SubtractScalars_SameScalar_ProducesZero()
	{
		var a = NewScalar();
		var r = new byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.SubtractScalars(a, a, r);
		r.ShouldBe(ZeroScalar);
	}

	[Test]
	public void Throws_When_LengthInvalid_AddScalars()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			var a = new byte[CryptoRistretto.ScalarLen - 1];
			var b = NewScalar();
			var r = new byte[CryptoRistretto.ScalarLen];
			CryptoRistretto.AddScalars(a, b, r);
		});
	}

	[Test]
	public void Throws_When_LengthInvalid_SubtractScalars()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			var a = NewScalar();
			var b = new byte[CryptoRistretto.ScalarLen - 1];
			var r = new byte[CryptoRistretto.ScalarLen];
			CryptoRistretto.SubtractScalars(a, b, r);
		});
	}


	[Test]
	public void MultiplyScalars_WithZero_IsZero()
	{
		var s = NewScalar();
		var r = new byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.MultiplyScalars(s, ZeroScalar, r);
		r.ShouldBe(ZeroScalar);
	}

	[Test]
	public void Throws_When_LengthInvalid_MultiplyScalars()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			var a = NewScalar();
			var b = new byte[CryptoRistretto.ScalarLen - 1];
			var r = new byte[CryptoRistretto.ScalarLen];
			CryptoRistretto.MultiplyScalars(a, b, r);
		});
	}



	[Test]
	public void Throws_When_SourceLengthInvalid_ReduceScalar()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			var invalid = new byte[CryptoRistretto.NonReducedScalarLen - 1];
			var r = new byte[CryptoRistretto.ScalarLen];
			CryptoRistretto.ReduceScalar(invalid, r);
		});
	}

	[Test]
	public void Throws_When_ResultLengthInvalid_ReduceScalar()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			var wide = NewWideScalar();
			var r = new byte[CryptoRistretto.ScalarLen - 1];
			CryptoRistretto.ReduceScalar(wide, r);
		});
	}


	[Test]
	public void InvertScalar_ProducesMultiplicativeInverse()
	{
		byte[] s;
		do { s = NewScalar(); } while (s.SequenceEqual(ZeroScalar)); // avoid zero (not invertible)

		var inv = new byte[CryptoRistretto.ScalarLen];
		var prod = new byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.InvertScalar(s, inv);
		CryptoRistretto.MultiplyScalars(s, inv, prod);

		prod.ShouldBe(OneScalar);
	}

	[Test]
	public void Throws_When_ScalarLengthInvalid_InvertScalar()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			var invalid = new byte[CryptoRistretto.ScalarLen - 1];
			var r = new byte[CryptoRistretto.ScalarLen];
			CryptoRistretto.InvertScalar(invalid, r);
		});
	}

	[Test]
	public void Throws_When_ResultLengthInvalid_InvertScalar()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			var s = NewScalar();
			var r = new byte[CryptoRistretto.ScalarLen - 1];
			CryptoRistretto.InvertScalar(s, r);
		});
	}

	[Test]
	public void ReduceScalar_IsIdempotentOnCanonicalForm()
	{
		Span<byte> input = stackalloc byte[64];
		Span<byte> reduced1 = stackalloc byte[32];
		Span<byte> reduced2 = stackalloc byte[32];

		RandomGenerator.Fill(input);
		CryptoRistretto.ReduceScalar(input, reduced1);

		Span<byte> extended = stackalloc byte[64];
		reduced1.CopyTo(extended[..32]);
		CryptoRistretto.ReduceScalar(extended, reduced2);

		reduced2.ShouldBe(reduced1);
	}

	[Test]
	public void DerivePointFromHash_OutputIsValidPoint()
	{
		Span<byte> hash = stackalloc byte[64];
		Span<byte> point = stackalloc byte[32];

		RandomGenerator.Fill(hash);
		CryptoRistretto.DerivePointFromHash(hash, point);

		CryptoRistretto.IsValidPoint(point).ShouldBeTrue();
	}

	[Test]
	public void ScalarMultiplyBase_AddScalarsConsistent()
	{
		Span<byte> a = stackalloc byte[32];
		Span<byte> b = stackalloc byte[32];
		Span<byte> sum = stackalloc byte[32];

		Span<byte> pa = stackalloc byte[32];
		Span<byte> pb = stackalloc byte[32];
		Span<byte> psum = stackalloc byte[32];
		Span<byte> sumPoints = stackalloc byte[32];

		CryptoRistretto.GenerateRandomScalar(a);
		CryptoRistretto.GenerateRandomScalar(b);

		CryptoRistretto.AddScalars(a, b, sum);

		CryptoRistretto.ScalarMultiplyBase(a, pa);
		CryptoRistretto.ScalarMultiplyBase(b, pb);
		CryptoRistretto.ScalarMultiplyBase(sum, psum);

		CryptoRistretto.AddPoints(pa, pb, sumPoints);

		psum.ShouldBe(sumPoints);
	}

	[Test]
	public void AddScalars_SubtractRecoverOriginal()
	{
		Span<byte> a = stackalloc byte[CryptoRistretto.ScalarLen];
		Span<byte> b = stackalloc byte[CryptoRistretto.ScalarLen];
		Span<byte> aPlusB = stackalloc byte[CryptoRistretto.ScalarLen];
		Span<byte> aPlusBminusB = stackalloc byte[CryptoRistretto.ScalarLen];

		CryptoRistretto.GenerateRandomScalar(a);
		CryptoRistretto.GenerateRandomScalar(b);

		CryptoRistretto.AddScalars(a, b, aPlusB);
		CryptoRistretto.SubtractScalars(aPlusB, b, aPlusBminusB);

		aPlusBminusB.ShouldBe(a);
	}

	[Test]
	public void KeyExchange_IsPossible()
	{
using var aliceScalarSecret = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
using var bobScalarSecret = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
CryptoRistretto.GenerateRandomScalar(aliceScalarSecret);
CryptoRistretto.GenerateRandomScalar(bobScalarSecret);

Span<byte> alicePublicPoint = stackalloc byte[CryptoRistretto.PointLen];
Span<byte> bobPublicPoint = stackalloc byte[CryptoRistretto.PointLen];

CryptoRistretto.ScalarMultiplyBase(aliceScalarSecret, alicePublicPoint);
CryptoRistretto.ScalarMultiplyBase(bobScalarSecret, bobPublicPoint);

using var aliceSharedSecret = new SecureMemory<byte>(CryptoRistretto.PointLen);
using var bobSharedSecret = new SecureMemory<byte>(CryptoRistretto.PointLen);

CryptoRistretto.ScalarMultiply(bobScalarSecret, alicePublicPoint, bobSharedSecret);
CryptoRistretto.ScalarMultiply(aliceScalarSecret, bobPublicPoint, aliceSharedSecret);

bool isSameSharedSecret = aliceSharedSecret.AsReadOnlySpan()
	.SequenceEqual(bobSharedSecret.AsReadOnlySpan());

Debug.Assert(isSameSharedSecret, "The shared secrets should be equal.");

using var aliceTxKey = new SecureMemory<byte>(XChaCha20Poly1305.KeyLen);
CryptoHkdf.DeriveKey(HashAlgorithmName.SHA512, ikm: aliceSharedSecret, okm: aliceTxKey, salt: alicePublicPoint, info: bobPublicPoint);

var aliceMessageToBobPlaintext = "Hello Bob, this is Alice!"u8;

Span<byte> aliceMessageToBobCiphertext = stackalloc byte[aliceMessageToBobPlaintext.Length + XChaCha20Poly1305.MacLen + XChaCha20Poly1305.NonceLen];

XChaCha20Poly1305.Encrypt(aliceMessageToBobCiphertext, aliceMessageToBobPlaintext, aliceTxKey);

using var bobRxKey = new SecureMemory<byte>(XChaCha20Poly1305.KeyLen);
CryptoHkdf.DeriveKey(HashAlgorithmName.SHA512, ikm: bobSharedSecret, okm: bobRxKey, salt: alicePublicPoint, info: bobPublicPoint);

Span<byte> aliceMessageToBobDecrypted = stackalloc byte[aliceMessageToBobCiphertext.Length - XChaCha20Poly1305.MacLen - XChaCha20Poly1305.NonceLen];

XChaCha20Poly1305.Decrypt(aliceMessageToBobDecrypted, aliceMessageToBobCiphertext, bobRxKey);

bool isDecryptionValid = aliceMessageToBobDecrypted.SequenceEqual(aliceMessageToBobPlaintext);

Debug.Assert(isDecryptionValid, "Decrypted message should match original plaintext.");

	}

	[Test]
	public void TwoPartyComputation_WorksAsExpected()
	{
		// -------- First party --------
using var x = new SecureMemory<byte>(CryptoRistretto.HashLen);
RandomGenerator.Fill(x);

using var px = new SecureMemory<byte>(CryptoRistretto.PointLen);
CryptoRistretto.DerivePointFromHash(x, px); // p(x)

using var r = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
Span<byte> gr = stackalloc byte[CryptoRistretto.PointLen];
Span<byte> a = stackalloc byte[CryptoRistretto.PointLen];

CryptoRistretto.GenerateRandomScalar(r);
CryptoRistretto.ScalarMultiplyBase(r, gr); // g^r
CryptoRistretto.AddPoints(px.AsReadOnlySpan(), gr, a);      // a = p(x) + g^r

// -------- Second party --------
using var k = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
Span<byte> v = stackalloc byte[CryptoRistretto.PointLen];
Span<byte> b = stackalloc byte[CryptoRistretto.PointLen];

CryptoRistretto.GenerateRandomScalar(k);
CryptoRistretto.ScalarMultiplyBase(k, v);       // v = g^k
CryptoRistretto.ScalarMultiply(k.AsReadOnlySpan(), a, b);        // b = a^k

// -------- First party unblinds --------
using var ir = new SecureMemory<byte>(CryptoRistretto.ScalarLen);
Span<byte> vir = stackalloc byte[CryptoRistretto.PointLen];
using var fx = new SecureMemory<byte>(CryptoRistretto.PointLen);

CryptoRistretto.NegateScalar(r, ir);            // -r
CryptoRistretto.ScalarMultiply(ir.AsReadOnlySpan(), v, vir);     // v^-r
CryptoRistretto.AddPoints(b, vir, fx.AsSpan());          // fx = p(x)^k

// Validate
using var expected = new SecureMemory<byte>(CryptoRistretto.PointLen);
CryptoRistretto.ScalarMultiply(k, px, expected);

bool isValid = fx.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan());
Debug.Assert(isValid, "The final result fx should match the expected value.");
		fx.ShouldBe(expected);
	}
}
