
using System.Text;
using LibSodium;
using LibSodium.Tests;

public class CryptoPasswordHashScryptTests
{
	[Test]
	public void HashPassword_And_VerifyPassword_ShouldSucceed()
	{
		string password = "correct horse battery staple";
		string hash = CryptoPasswordHashScrypt.HashPassword(password);
		CryptoPasswordHashScrypt.VerifyPassword(hash, password).ShouldBeTrue();
	}

	[Test]
	public void HashPassword_SpanOverload_ShouldSucceed()
	{
		Span<byte> password = stackalloc byte[] { 100, 101, 102 };
		string hash = CryptoPasswordHashScrypt.HashPassword(password);
		CryptoPasswordHashScrypt.VerifyPassword(hash, password).ShouldBeTrue();
	}

	[Test]
	public void HashPassword_SpanOverload_WithTooFewIterations_ShouldThrow()
	{

		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
		{
			Span<byte> password = stackalloc byte[] { 1 };
			CryptoPasswordHashScrypt.HashPassword(password, iterations: CryptoPasswordHashScrypt.MinIterations - 1);
		});
	}

	[Test]
	public void HashPassword_SpanOverload_WithTooLittleMemory_ShouldThrow()
	{
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
		{
			Span<byte> password = stackalloc byte[] { 1 };
			CryptoPasswordHashScrypt.HashPassword(password, requiredMemoryLen: CryptoPasswordHashScrypt.MinMemoryLen - 1);
		});
	}

	[Test]
	public void VerifyPassword_SpanOverload_WithInvalidHash_ShouldReturnFalse()
	{
		Span<byte> password = stackalloc byte[] { 1, 2, 3 };
		string hash = "invalid$7$hash...";
		CryptoPasswordHashScrypt.VerifyPassword(hash, password).ShouldBeFalse();
	}

	[Test]
	public void HashPassword_SamePassword_ProducesDifferentHashes()
	{
		string password = "same-password";
		string hash1 = CryptoPasswordHashScrypt.HashPassword(password);
		string hash2 = CryptoPasswordHashScrypt.HashPassword(password);
		hash1.ShouldNotBe(hash2);
	}



	[Test]
	public void VerifyPassword_WithTamperedHash_ShouldFail()
	{
		string password = "secure";
		string hash = CryptoPasswordHashScrypt.HashPassword(password);
		var tampered = hash[..^2] + (hash[^2] == 'a' ? 'b' : 'a');
		CryptoPasswordHashScrypt.VerifyPassword(tampered, password).ShouldBeFalse();
	}


	[Test]
	public void VerifyPassword_SpanOverload_WithWrongPassword_ShouldFail()
	{
		var password = Encoding.UTF8.GetBytes("right");
		var wrong = Encoding.UTF8.GetBytes("wrong");
		var hash = CryptoPasswordHashScrypt.HashPassword(password);
		CryptoPasswordHashScrypt.VerifyPassword(hash, wrong).ShouldBeFalse();
	}


	[Test]
	public void DeriveKey_WithSameInputs_ProducesSameKey()
	{
		string password = "same-password";
		Span<byte> salt = stackalloc byte[CryptoPasswordHashScrypt.SaltLen];
		RandomGenerator.Fill(salt);
		Span<byte> key1 = stackalloc byte[32];
		Span<byte> key2 = stackalloc byte[32];

		CryptoPasswordHashScrypt.DeriveKey(key1, password, salt);
		CryptoPasswordHashScrypt.DeriveKey(key2, password, salt);

		key1.ShouldBe(key2);
	}


	[Test]
	public void DeriveKey_WithShortSalt_ShouldThrow()
	{
		var salt = new byte[CryptoPasswordHashScrypt.SaltLen - 1];
		var key = new byte[32];
		AssertLite.Throws<ArgumentException>(() =>
			CryptoPasswordHashScrypt.DeriveKey(key, "x", salt));
	}


	[Test]
	public void DeriveKey_WithShortKey_ShouldThrow()
	{
		var salt = new byte[CryptoPasswordHashScrypt.SaltLen];
		var key = new byte[CryptoPasswordHashScrypt.MinKeyLen - 1];
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashScrypt.DeriveKey(key, "x", salt));
	}

	[Test]
	public void DeriveKey_WithTooFewIterations_ShouldThrow()
	{
		var salt = new byte[CryptoPasswordHashScrypt.SaltLen];
		var key = new byte[32];
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashScrypt.DeriveKey(key, "x", salt, CryptoPasswordHashScrypt.MinIterations - 1));
	}

	[Test]
	public void DeriveKey_WithTooLittleMemory_ShouldThrow()
	{
		var salt = new byte[CryptoPasswordHashScrypt.SaltLen];
		var key = new byte[32];
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashScrypt.DeriveKey(key, "x", salt, requiredMemoryLen: CryptoPasswordHashScrypt.MinMemoryLen - 1));
	}

	[Test]
	public void HashPassword_WithTooFewIterations_ShouldThrow()
	{
		string password = "pw";
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashScrypt.HashPassword(password, iterations: CryptoPasswordHashScrypt.MinIterations - 1));
	}


	[Test]
	public void HashPassword_WithTooLittleMemory_ShouldThrow()
	{
		string password = "pw";
		AssertLite.Throws<ArgumentOutOfRangeException>(() =>
			CryptoPasswordHashScrypt.HashPassword(password, requiredMemoryLen: CryptoPasswordHashScrypt.MinMemoryLen - 1));
	}

	[Test]
	public void VerifyPassword_WithNullHash_ShouldThrow()
	{
		AssertLite.Throws<ArgumentNullException>(() =>
			CryptoPasswordHashScrypt.VerifyPassword(null!, "pw"));
	}



	[Test]
	public void VerifyPassword_WithTruncatedHash_ShouldReturnFalse()
	{
		string password = "pw";
		string hash = CryptoPasswordHashScrypt.HashPassword(password);
		string truncated = hash.Substring(0, 10);
		CryptoPasswordHashScrypt.VerifyPassword(truncated, password).ShouldBeFalse();
	}

	[Test]
	public void DeriveKey_WithMinProfile_ShouldSucceed()
	{
		Span<byte> salt = stackalloc byte[CryptoPasswordHashScrypt.SaltLen];
		Span<byte> key = stackalloc byte[32];
		RandomGenerator.Fill(salt);

		CryptoPasswordHashScrypt.DeriveKey(key, "min", salt,
			CryptoPasswordHashScrypt.MinIterations, CryptoPasswordHashScrypt.MinMemoryLen);

		SecureMemory.IsZero(key).ShouldBeFalse();
	}


	[Test]
	public void DeriveKey_WithInteractiveProfile_ShouldSucceed()
	{
		Span<byte> salt = stackalloc byte[CryptoPasswordHashScrypt.SaltLen];
		Span<byte> key = stackalloc byte[32];
		RandomGenerator.Fill(salt);

		CryptoPasswordHashScrypt.DeriveKey(key, "interactive", salt,
			CryptoPasswordHashScrypt.InteractiveIterations, CryptoPasswordHashScrypt.InteractiveMemoryLen);

		SecureMemory.IsZero(key).ShouldBeFalse();
	}


	[Test]
	public void DeriveKey_WithModerateProfile_ShouldSucceed()
	{
		Span<byte> salt = stackalloc byte[CryptoPasswordHashScrypt.SaltLen];
		Span<byte> key = stackalloc byte[32];
		RandomGenerator.Fill(salt);

		CryptoPasswordHashScrypt.DeriveKey(key, "moderate", salt,
			CryptoPasswordHashScrypt.ModerateIterations, CryptoPasswordHashScrypt.ModerateMemoryLen);

		SecureMemory.IsZero(key).ShouldBeFalse();
	}



	[Test]
	public void DeriveKey_WithSensitiveProfile_ShouldSucceed()
	{
		Span<byte> salt = stackalloc byte[CryptoPasswordHashScrypt.SaltLen];
		Span<byte> key = stackalloc byte[32];
		RandomGenerator.Fill(salt);

		CryptoPasswordHashScrypt.DeriveKey(key, "sensitive", salt,
			CryptoPasswordHashScrypt.SensitiveIterations, CryptoPasswordHashScrypt.SensitiveMemoryLen);

		SecureMemory.IsZero(key).ShouldBeFalse();
	}

	[Test]
	public void HashPassword_WithMinProfile_ShouldSucceed()
	{
		string password = "pw-min";
		string hash = CryptoPasswordHashScrypt.HashPassword(password,
			CryptoPasswordHashScrypt.MinIterations,
			CryptoPasswordHashScrypt.MinMemoryLen);

		CryptoPasswordHashScrypt.VerifyPassword(hash, password).ShouldBeTrue();
	}

	[Test]
	public void HashPassword_WithInteractiveProfile_ShouldSucceed()
	{
		string password = "pw-interactive";
		string hash = CryptoPasswordHashScrypt.HashPassword(password,
			CryptoPasswordHashScrypt.InteractiveIterations,
			CryptoPasswordHashScrypt.InteractiveMemoryLen);

		CryptoPasswordHashScrypt.VerifyPassword(hash, password).ShouldBeTrue();
	}

	[Test]
	public void HashPassword_WithModerateProfile_ShouldSucceed()
	{
		string password = "pw-moderate";
		string hash = CryptoPasswordHashScrypt.HashPassword(password,
			CryptoPasswordHashScrypt.ModerateIterations,
			CryptoPasswordHashScrypt.ModerateMemoryLen);

		CryptoPasswordHashScrypt.VerifyPassword(hash, password).ShouldBeTrue();
	}

	[Test]
	public void HashPassword_WithSensitiveProfile_ShouldSucceed()
	{
		string password = "pw-sensitive";
		string hash = CryptoPasswordHashScrypt.HashPassword(password,
			CryptoPasswordHashScrypt.SensitiveIterations,
			CryptoPasswordHashScrypt.SensitiveMemoryLen);

		CryptoPasswordHashScrypt.VerifyPassword(hash, password).ShouldBeTrue();
	}


}
