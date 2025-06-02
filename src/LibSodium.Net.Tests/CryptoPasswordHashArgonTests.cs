using System.Text;
using LibSodium;
using LibSodium.Tests;

public class CryptoPasswordHashArgonTests
{
	[Test]
	public void DeriveKey_SpanOverload_WithSameInputs_ProducesSameKey()
	{
		Span<byte> salt = stackalloc byte[CryptoPasswordHashArgon.SaltLen];
		RandomGenerator.Fill(salt);
		Span<byte> key1 = stackalloc byte[32];
		Span<byte> key2 = stackalloc byte[32];
		byte[] passwordBytes = Encoding.UTF8.GetBytes("span-password");

		CryptoPasswordHashArgon.DeriveKey(key1, passwordBytes, salt);
		CryptoPasswordHashArgon.DeriveKey(key2, passwordBytes, salt);

		key1.ShouldBe(key2);
	}

	[Test]
	public void HashPassword_HasExpectedPrefix()
	{
		string hash = CryptoPasswordHashArgon.HashPassword("prefix-check");
		hash.ShouldStartWith(CryptoPasswordHashArgon.Prefix);
	}

	[Test]
	public void HashPassword_SamePassword_ProducesDifferentHashes()
	{
		string password = "non-deterministic";
		string hash1 = CryptoPasswordHashArgon.HashPassword(password);
		string hash2 = CryptoPasswordHashArgon.HashPassword(password);

		hash1.ShouldNotBe(hash2);
	}

	[Test]
	public void VerifyPassword_WithTamperedHash_ShouldFail()
	{
		string password = "tamper-proof";
		string hash = CryptoPasswordHashArgon.HashPassword(password);

		char[] chars = hash.ToCharArray();
		chars[^2] = chars[^2] == 'a' ? 'b' : 'a';
		string tampered = new string(chars);

		CryptoPasswordHashArgon.VerifyPassword(tampered, password).ShouldBeFalse();
	}

	[Test]
	public void HashPassword_SpanOverload_And_VerifyPassword_Succeeds()
	{
		byte[] passwordBytes = Encoding.UTF8.GetBytes("span-pass-hash");

		string hash = CryptoPasswordHashArgon.HashPassword(passwordBytes);

		CryptoPasswordHashArgon.VerifyPassword(hash, passwordBytes).ShouldBeTrue();
	}

	[Test]
	public void VerifyPassword_SpanOverload_WithWrongPassword_ShouldFail()
	{
		byte[] password = Encoding.UTF8.GetBytes("right-pass");
		byte[] wrong = Encoding.UTF8.GetBytes("wrong-pass");

		string hash = CryptoPasswordHashArgon.HashPassword(password);

		CryptoPasswordHashArgon.VerifyPassword(hash, wrong).ShouldBeFalse();
	}

	[Test]
	public void DeriveKey_WithValidInputs_ShouldFillKey()
	{
		Span<byte> key = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[CryptoPasswordHashArgon.SaltLen];
		string password = "p@ssw0rd!";

		RandomGenerator.Fill(salt);
		CryptoPasswordHashArgon.DeriveKey(key, password, salt);
		SecureMemory.IsZero(key).ShouldBeFalse();
	}

	[Test]
	public void DeriveKey_WithDifferentSalts_ProducesDifferentKeys()
	{
		string password = Guid.NewGuid().ToString();
		Span<byte> salt1 = stackalloc byte[CryptoPasswordHashArgon.SaltLen];
		Span<byte> salt2 = stackalloc byte[CryptoPasswordHashArgon.SaltLen];
		RandomGenerator.Fill(salt1);
		RandomGenerator.Fill(salt2);

		Span<byte> key1 = stackalloc byte[32];
		Span<byte> key2 = stackalloc byte[32];

		CryptoPasswordHashArgon.DeriveKey(key1, password, salt1);
		CryptoPasswordHashArgon.DeriveKey(key2, password, salt2);

		key1.ShouldNotBe(key2);
	}

	[Test]
	public void DeriveKey_WithDifferentPasswords_ProducesDifferentKeys()
	{
		string password1 = Guid.NewGuid().ToString();
		string password2 = Guid.NewGuid().ToString();
		Span<byte> salt = stackalloc byte[CryptoPasswordHashArgon.SaltLen];
		RandomGenerator.Fill(salt);

		Span<byte> key1 = stackalloc byte[32];
		Span<byte> key2 = stackalloc byte[32];

		CryptoPasswordHashArgon.DeriveKey(key1, password1, salt);
		CryptoPasswordHashArgon.DeriveKey(key2, password2, salt);

		key1.ShouldNotBe(key2);
	}

	[Test]
	public void DeriveKey_WithSameInputs_ProducesSameKey()
	{
		string password = Guid.NewGuid().ToString();
		Span<byte> salt = stackalloc byte[CryptoPasswordHashArgon.SaltLen];
		RandomGenerator.Fill(salt);

		Span<byte> key1 = stackalloc byte[32];
		Span<byte> key2 = stackalloc byte[32];

		CryptoPasswordHashArgon.DeriveKey(key1, password, salt);
		CryptoPasswordHashArgon.DeriveKey(key2, password, salt);

		key1.ShouldBe(key2);
	}

	[Test]
	public void DeriveKey_WithShortSalt_ShouldThrow()
	{
		byte[] key = new byte[32];
		string password = "correcthorsebatterystaple";
		byte[] salt = new byte[CryptoPasswordHashArgon.SaltLen - 1];

		AssertLite.Throws<ArgumentException>(() => CryptoPasswordHashArgon.DeriveKey(key, password, salt));
	}

	[Test]
	public void HashPassword_And_VerifyPassword_ShouldSucceed()
	{
		string password = "correct horse battery staple";

		string hash = CryptoPasswordHashArgon.HashPassword(password);

		CryptoPasswordHashArgon.VerifyPassword(hash, password).ShouldBeTrue();
	}

	[Test]
	public void VerifyPassword_WithWrongPassword_ShouldFail()
	{
		string password = "super secret";
		string wrongPassword = "not the same";

		string hash = CryptoPasswordHashArgon.HashPassword(password);

		CryptoPasswordHashArgon.VerifyPassword(hash, wrongPassword).ShouldBeFalse();
	}

	[Test]
	public void HashPassword_WithEmptyPassword_IsValid()
	{
		string password = string.Empty;

		string hash = CryptoPasswordHashArgon.HashPassword(password);

		CryptoPasswordHashArgon.VerifyPassword(hash, password).ShouldBeTrue();
	}
	// tests nuevos

	[Test]
	public void DeriveKey_WithInvalidKeyLength_ShouldThrow()
	{
		var key = new byte[CryptoPasswordHashArgon.MinKeyLen - 1];
		var salt = new byte[CryptoPasswordHashArgon.SaltLen];
		string password = "short-key";
		RandomGenerator.Fill(salt);

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashArgon.DeriveKey(key, password, salt));
	}

	[Test]
	public void DeriveKey_WithTooFewIterations_ShouldThrow()
	{
		var key = new byte[32];
		var salt = new byte[CryptoPasswordHashArgon.SaltLen];
		string password = "few-iters";
		RandomGenerator.Fill(salt);

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashArgon.DeriveKey(key, password, salt, iterations: CryptoPasswordHashArgon.MinIterations - 1));
	}

	[Test]
	public void DeriveKey_WithTooLittleMemory_ShouldThrow()
	{
		var key = new byte[32];
		var salt = new byte[CryptoPasswordHashArgon.SaltLen];
		string password = "low-mem";
		RandomGenerator.Fill(salt);

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashArgon.DeriveKey(key, password, salt, requiredMemoryLen: CryptoPasswordHashArgon.MinMemoryLen - 1));
	}

	[Test]
	public void DeriveKey_WithArgon2i13_And_TooFewIterations_ShouldThrow()
	{
		var key = new byte[32];
		var salt = new byte[CryptoPasswordHashArgon.SaltLen];
		string password = "argon2i-fail";
		RandomGenerator.Fill(salt);

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashArgon.DeriveKey(key, password, salt,
				iterations: 2,
				algorithm: PasswordHashArgonAlgorithm.Argon2i13));
	}

	[Test]
	public void DeriveKey_WithArgon2id13_ShouldSucceed()
	{
		var key = new byte[32];
		var salt = new byte[CryptoPasswordHashArgon.SaltLen];
		string password = "argon2id-ok";
		RandomGenerator.Fill(salt);

		CryptoPasswordHashArgon.DeriveKey(key, password, salt,
			iterations: 4,
			requiredMemoryLen: CryptoPasswordHashArgon.ModerateMemoryLen,
			algorithm: PasswordHashArgonAlgorithm.Argon2id13);

		SecureMemory.IsZero(key).ShouldBeFalse();
	}

	[Test]
	public void DeriveKey_WithArgon2i13_ShouldSucceed()
	{
		Span<byte> key = stackalloc byte[32];
		Span<byte> salt = stackalloc byte[CryptoPasswordHashArgon.SaltLen];
		string password = "argon2i-ok";
		RandomGenerator.Fill(salt);

		CryptoPasswordHashArgon.DeriveKey(key, password, salt,
			iterations: 3,
			requiredMemoryLen: CryptoPasswordHashArgon.ModerateMemoryLen,
			algorithm: PasswordHashArgonAlgorithm.Argon2i13);

		SecureMemory.IsZero(key).ShouldBeFalse();
	}

	// more tests
	[Test]
	public void HashPassword_WithTooFewIterations_ShouldThrow()
	{
		string password = "p";

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashArgon.HashPassword(password, iterations: CryptoPasswordHashArgon.MinIterations - 1));
	}

	[Test]
	public void HashPassword_WithTooLittleMemory_ShouldThrow()
	{
		string password = "p";

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashArgon.HashPassword(password, requiredMemoryLen: CryptoPasswordHashArgon.MinMemoryLen - 1));
	}

	[Test]
	public void HashPassword_SpanOverload_WithTooFewIterations_ShouldThrow()
	{
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
		{
			Span<byte> password = stackalloc byte[1];
			CryptoPasswordHashArgon.HashPassword(password, iterations: CryptoPasswordHashArgon.MinIterations - 1);
		});
	}

	[Test]
	public void HashPassword_SpanOverload_WithTooLittleMemory_ShouldThrow()
	{
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
		{
			Span<byte> password = stackalloc byte[1];
			CryptoPasswordHashArgon.HashPassword(password, requiredMemoryLen: CryptoPasswordHashArgon.MinMemoryLen - 1);
		});
	}

	[Test]
	public void VerifyPassword_WithNullHash_ShouldThrow()
	{
		string password = "pw";

		AssertLite.Throws<ArgumentNullException>(() =>
			CryptoPasswordHashArgon.VerifyPassword(null!, password));
	}

	[Test]
	public void VerifyPassword_WithInvalidPrefix_ShouldReturnFalse()
	{
		string password = "pw";
		string hash = "invalidprefix$argon2id...";

		CryptoPasswordHashArgon.VerifyPassword(hash, password).ShouldBeFalse();
	}

	[Test]
	public void VerifyPassword_WithTruncatedHash_ShouldReturnFalse()
	{
		string password = "pw";
		string hash = CryptoPasswordHashArgon.HashPassword(password).Substring(0, 10);

		CryptoPasswordHashArgon.VerifyPassword(hash, password).ShouldBeFalse();
	}

	[Test]
	public void VerifyPassword_SpanOverload_WithInvalidPrefix_ShouldReturnFalse()
	{
		Span<byte> password = stackalloc byte[] { 1, 2, 3 };
		string hash = "badprefix$argon2id...";

		CryptoPasswordHashArgon.VerifyPassword(hash, password).ShouldBeFalse();
	}

	[Test]
	public void DeriveKey_WithSecureMemoryInputs_ShouldSucceed()
	{
		using var key = SecureMemory.Create<byte>(32);
		using var pwd = SecureMemory.Create<byte>(16);
		Span<byte> salt = stackalloc byte[CryptoPasswordHashArgon.SaltLen];
		RandomGenerator.Fill(pwd);
		RandomGenerator.Fill(salt);

		CryptoPasswordHashArgon.DeriveKey(key, pwd, salt);
		key.AsSpan().ShouldNotBeZero();
	}

	[Test]
	public void DeriveKey_WithSecureMemoryInputs_SameInputs_ProducesSameKey()
	{
		using var key1 = SecureMemory.Create<byte>(32);
		using var key2 = SecureMemory.Create<byte>(32);
		using var pwd = SecureMemory.Create<byte>(16);
		Span<byte> salt = stackalloc byte[CryptoPasswordHashArgon.SaltLen];
		RandomGenerator.Fill(pwd);
		RandomGenerator.Fill(salt);

		CryptoPasswordHashArgon.DeriveKey(key1, pwd, salt);
		CryptoPasswordHashArgon.DeriveKey(key2, pwd, salt);

		key1.AsSpan().ShouldBe(key2.AsSpan());
	}

	[Test]
	public void HashPassword_WithSecureMemory_Succeeds()
	{
		using var pwd = SecureMemory.Create<byte>(16);
		RandomGenerator.Fill(pwd);

		string hash = CryptoPasswordHashArgon.HashPassword(pwd);
		hash.ShouldStartWith(CryptoPasswordHashArgon.Prefix);
	}

	[Test]
	public void VerifyPassword_WithSecureMemory_Succeeds()
	{
		using var pwd = SecureMemory.Create<byte>(16);
		RandomGenerator.Fill(pwd);

		string hash = CryptoPasswordHashArgon.HashPassword(pwd);
		CryptoPasswordHashArgon.VerifyPassword(hash, pwd).ShouldBeTrue();
	}

	[Test]
	public void VerifyPassword_WithWrongSecureMemory_ShouldFail()
	{
		using var pwd1 = SecureMemory.Create<byte>(16);
		using var pwd2 = SecureMemory.Create<byte>(16);
		RandomGenerator.Fill(pwd1);
		RandomGenerator.Fill(pwd2);

		string hash = CryptoPasswordHashArgon.HashPassword(pwd1);
		CryptoPasswordHashArgon.VerifyPassword(hash, pwd2).ShouldBeFalse();
	}

}
