using LibSodium.Tests;
using static System.Security.Cryptography.HashAlgorithmName;
using SysCrypto = System.Security.Cryptography;

public class HKDFTests
{
	private static void FillRandom(Span<byte> buffer)
	{
		LibSodium.RandomGenerator.Fill(buffer);
	}

	[Test]
	public void DeriveKey_Matches_System_SHA256()
	{
		Span<byte> ikm = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[16];
		Span<byte> info = stackalloc byte[12];
		Span<byte> actualOkm = stackalloc byte[32];
		Span<byte> expectedOkm = stackalloc byte[32];

		FillRandom(ikm);
		FillRandom(salt);
		FillRandom(info);

		LibSodium.HKDF.DeriveKey(SHA256, ikm, actualOkm, salt, info);
		SysCrypto.HKDF.DeriveKey(SHA256, ikm, expectedOkm, salt, info);

		actualOkm.ShouldBe(expectedOkm);
	}

	[Test]
	public void DeriveKey_Matches_System_SHA512()
	{
		Span<byte> ikm = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[16];
		Span<byte> info = stackalloc byte[12];
		Span<byte> actualOkm = stackalloc byte[64];
		Span<byte> expectedOkm = stackalloc byte[64];

		FillRandom(ikm);
		FillRandom(salt);
		FillRandom(info);

		LibSodium.HKDF.DeriveKey(SHA512, ikm, actualOkm, salt, info);
		SysCrypto.HKDF.DeriveKey(SHA512, ikm, expectedOkm, salt, info);

		actualOkm.ShouldBe(expectedOkm);
	}

	[Test]
	public void Extract_Matches_System_SHA256()
	{
		Span<byte> ikm = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[16];
		Span<byte> expectedPrk = stackalloc byte[LibSodium.HKDF.Sha256PrkLen];
		Span<byte> actualPrk = stackalloc byte[LibSodium.HKDF.Sha256PrkLen];
		FillRandom(ikm);
		FillRandom(salt);
		LibSodium.HKDF.Extract(SHA256, ikm, salt, actualPrk);
		SysCrypto.HKDF.Extract(SHA256, ikm, salt, expectedPrk);
		expectedPrk.ShouldBe(expectedPrk);
	}

	[Test]
	public void Extract_Matches_System_SHA512()
	{
		Span<byte> ikm = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[16];
		Span<byte> expectedPrk = stackalloc byte[LibSodium.HKDF.Sha512PrkLen];
		Span<byte> actualPrk = stackalloc byte[LibSodium.HKDF.Sha512PrkLen];
		FillRandom(ikm);
		FillRandom(salt);
		LibSodium.HKDF.Extract(SHA512, ikm, salt, actualPrk);
		SysCrypto.HKDF.Extract(SHA512, ikm, salt, expectedPrk);
		expectedPrk.ShouldBe(expectedPrk);
	}

	[Test]
	public void Expand_Matches_System_SHA256()
	{
		Span<byte> prk = stackalloc byte[LibSodium.HKDF.Sha256PrkLen];
		Span<byte> info = stackalloc byte[12];
		Span<byte> expectedOkm = stackalloc byte[32];
		Span<byte> actualOkm = stackalloc byte[32];
		FillRandom(prk);
		FillRandom(info);
		LibSodium.HKDF.Expand(SHA256, prk, actualOkm, info);
		SysCrypto.HKDF.Expand(SHA256, prk, expectedOkm, info);
		actualOkm.ShouldBe(expectedOkm);
	}

	[Test]
	public void Expand_Matches_System_SHA512()
	{
		Span<byte> prk = stackalloc byte[LibSodium.HKDF.Sha512PrkLen];
		Span<byte> info = stackalloc byte[12];
		Span<byte> expectedOkm = stackalloc byte[32];
		Span<byte> actualOkm = stackalloc byte[32];
		FillRandom(prk);
		FillRandom(info);
		LibSodium.HKDF.Expand(SHA512, prk, actualOkm, info);
		SysCrypto.HKDF.Expand(SHA512, prk, expectedOkm, info);
		actualOkm.ShouldBe(expectedOkm);
	}

	[Test]
	public void DeriveKey_IsDeterministic()
	{
		Span<byte> ikm = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[16];
		Span<byte> info = stackalloc byte[12];
		Span<byte> okm1 = stackalloc byte[64];
		Span<byte> okm2 = stackalloc byte[64];
		FillRandom(ikm);
		FillRandom(salt);
		FillRandom(info);
		LibSodium.HKDF.DeriveKey(SHA512, ikm, okm1, salt, info);
		LibSodium.HKDF.DeriveKey(SHA512, ikm, okm2, salt, info);
		okm1.ShouldBe(okm2);
	}

	[Test]
	public void DeriveKey_DifferentSalt_ProducesDifferentKeys()
	{
		Span<byte> ikm = stackalloc byte[32];
		Span<byte> salt1 = stackalloc byte[16];
		Span<byte> salt2 = stackalloc byte[16];
		Span<byte> info = stackalloc byte[12];
		Span<byte> okm1 = stackalloc byte[32];
		Span<byte> okm2 = stackalloc byte[32];
		FillRandom(ikm);
		FillRandom(salt1);
		FillRandom(salt2);
		FillRandom(info);
		LibSodium.HKDF.DeriveKey(SHA256, ikm, okm1, salt1, info);
		LibSodium.HKDF.DeriveKey(SHA256, ikm, okm2, salt2, info);
		okm1.ShouldNotBe(okm2);
	}

	[Test]
	public void DeriveKey_DifferentInfo_ProducesDifferentKeys()
	{
		Span<byte> ikm = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[16];
		Span<byte> info1 = stackalloc byte[12];
		Span<byte> info2 = stackalloc byte[12];
		Span<byte> okm1 = stackalloc byte[32];
		Span<byte> okm2 = stackalloc byte[32];
		FillRandom(ikm);
		FillRandom(salt);
		FillRandom(info1);
		FillRandom(info2);
		LibSodium.HKDF.DeriveKey(SHA256, ikm, okm1, salt, info1);
		LibSodium.HKDF.DeriveKey(SHA256, ikm, okm2, salt, info2);
		okm1.ShouldNotBe(okm2);
	}

	[Test]
	public void DeriveKey_BoundaryLengths_Succeed()
	{
		Span<byte> ikm = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[16];
		Span<byte> info = stackalloc byte[12];
		FillRandom(ikm);
		FillRandom(salt);
		FillRandom(info);

		Span<byte> minOkm = stackalloc byte[LibSodium.HKDF.MinOkmLen];
		Span<byte> maxOkm = new byte[LibSodium.HKDF.Sha256MaxOkmLen];

		LibSodium.HKDF.DeriveKey(SHA256, ikm, minOkm, salt, info);
		LibSodium.HKDF.DeriveKey(SHA256, ikm, maxOkm, salt, info);

		minOkm.ShouldNotBeZero();
		maxOkm.ShouldNotBeZero();
	}

	[Test]
	public void Expand_InvalidPrkLength_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> prk = stackalloc byte[31];
			Span<byte> okm = stackalloc byte[32];
			Span<byte> info = stackalloc byte[8];
			LibSodium.HKDF.Expand(SHA256, prk, okm, info);
		});
	}

	[Test]
	public void Expand_OkmLengthTooSmall_Throws()
	{
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
		{
			Span<byte> prk = stackalloc byte[32];
			Span<byte> okm = stackalloc byte[3];
			Span<byte> info = stackalloc byte[8];
			LibSodium.HKDF.Expand(SHA256, prk, okm, info);
		});
	}

	[Test]
	public void Expand_OkmLengthTooLarge_Throws()
	{
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
		{
			Span<byte> prk = stackalloc byte[32];
			Span<byte> okm = new byte[LibSodium.HKDF.Sha256MaxOkmLen + 1];
			Span<byte> info = stackalloc byte[8];
			LibSodium.HKDF.Expand(SHA256, prk, okm, info);
		});
	}

	[Test]
	public void DeriveKey_Stream_Equals_OneShot()
	{
		var ikm = new byte[5000];
		Span<byte> salt = stackalloc byte[16];
		Span<byte> info = stackalloc byte[12];
		Span<byte> expectedOkm = stackalloc byte[32];
		Span<byte> actualOkm = new byte[32];

		FillRandom(ikm);
		FillRandom(salt);
		FillRandom(info);

		LibSodium.HKDF.DeriveKey(SHA256, ikm, expectedOkm, salt, info);

		using var ikmStream = new MemoryStream(ikm, writable: false);
		LibSodium.HKDF.DeriveKey(SHA256, ikmStream, actualOkm, salt, info);

		actualOkm.ShouldBe(expectedOkm);
	}

	[Test]
	public async Task DeriveKeyAsync_Stream_Equals_OneShot()
	{
		var ikm = new byte[5000];
		var salt = new byte[16];
		var info = new byte[12];
		var expectedOkm = new byte[32];
		var actualOkm = new byte[32];

		FillRandom(ikm);
		FillRandom(salt);
		FillRandom(info);

		LibSodium.HKDF.DeriveKey(SHA256, ikm, expectedOkm, salt, info);

		using var ikmStream = new MemoryStream(ikm, writable: false);
		await LibSodium.HKDF.DeriveKeyAsync(SHA256, ikmStream, actualOkm, salt, info);

		actualOkm.ShouldBe(expectedOkm);
	}

	[Test]
	public void Expand_Sha256_MinOkmLen_Succeeds()
	{
		Span<byte> prk = stackalloc byte[LibSodium.HKDF.Sha256PrkLen];
		Span<byte> okm = stackalloc byte[LibSodium.HKDF.MinOkmLen];
		Span<byte> info = stackalloc byte[4];
		FillRandom(prk);
		FillRandom(info);
		LibSodium.HKDF.Expand(SHA256, prk, okm, info);
	}

	[Test]
	public void Expand_Sha512_MaxOkmLen_Succeeds()
	{
		Span<byte> prk = stackalloc byte[LibSodium.HKDF.Sha512PrkLen];
		Span<byte> okm = new byte[LibSodium.HKDF.Sha512MaxOkmLen];
		Span<byte> info = stackalloc byte[8];
		FillRandom(prk);
		FillRandom(info);
		LibSodium.HKDF.Expand(SHA512, prk, okm, info);
	}

	[Test]
	public void Extract_InvalidPrkLength_Throws_SHA256()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> ikm = stackalloc byte[32];
			Span<byte> salt = stackalloc byte[16];
			Span<byte> prk = stackalloc byte[16];
			LibSodium.HKDF.Extract(SHA256, ikm, salt, prk);
		});
	}

	[Test]
	public void Expand_InvalidPrkLength_Throws_SHA512()
	{

		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> prk = stackalloc byte[32];
			Span<byte> okm = stackalloc byte[64];
			Span<byte> info = stackalloc byte[12];
			LibSodium.HKDF.Expand(SHA512, prk, okm, info);
		});
	}

	[Test]
	public void Expand_OkmTooShort_Throws()
	{

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
		{
			Span<byte> prk = stackalloc byte[LibSodium.HKDF.Sha256PrkLen];
			Span<byte> okm = stackalloc byte[2];
			Span<byte> info = stackalloc byte[4];
			LibSodium.HKDF.Expand(SHA256, prk, okm, info);
		});
	}

	[Test]
	public void Expand_OkmTooLong_Throws_SHA512()
	{

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
		{
			Span<byte> prk = stackalloc byte[LibSodium.HKDF.Sha512PrkLen];
			Span<byte> okm = new byte[LibSodium.HKDF.Sha512MaxOkmLen + 1];
			Span<byte> info = stackalloc byte[8];
			LibSodium.HKDF.Expand(SHA512, prk, okm, info);
		});
	}

	[Test]
	public void Expand_UnsupportedHashAlgorithm_Throws()
	{
		AssertLite.Throws<NotSupportedException>(() =>
		{
			Span<byte> prk = stackalloc byte[LibSodium.HKDF.Sha256PrkLen];
			Span<byte> okm = stackalloc byte[32];
			Span<byte> info = stackalloc byte[4];
			LibSodium.HKDF.Expand(new ("SHA1"), prk, okm, info);
		});
	}

}
