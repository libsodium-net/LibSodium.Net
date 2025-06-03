using System;
using System.Text;
using LibSodium;
using LibSodium.Tests;
using TUnit;

public class CryptoKeyDerivationTests
{
	[Test]
	public void GenerateMasterKey_CorrectLength_Succeeds()
	{
		Span<byte> key = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		CryptoKeyDerivation.GenerateMasterKey(key);
		key.ShouldNotBeZero();
	}

	[Test]
	public void GenerateMasterKey_WrongLength_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> key = stackalloc byte[CryptoKeyDerivation.MasterKeyLen - 1];
			CryptoKeyDerivation.GenerateMasterKey(key);
		});
	}

	[Test]
	public void DeriveSubkey_ValidInputs_Succeeds()
	{
		Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> context = stackalloc byte[CryptoKeyDerivation.ContextLen];
		RandomGenerator.Fill(masterKey);
		context[0] = (byte)'A';

		CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 42, context);
		subkey.ShouldNotBeZero();
	}

	[Test]
	public void DeriveSubkey_SubkeyTooShort_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen - 1];
			Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
			Span<byte> context = stackalloc byte[CryptoKeyDerivation.ContextLen];
			CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 0, context);
		});
	}

	[Test]
	public void DeriveSubkey_ContextTooShort_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
			Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
			Span<byte> context = stackalloc byte[CryptoKeyDerivation.ContextLen - 1];
			CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 0, context);
		});
	}

	[Test]
	public void DeriveSubkey_MasterKeyTooShort_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
			Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen - 1];
			Span<byte> context = stackalloc byte[CryptoKeyDerivation.ContextLen];
			CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 0, context);
		});
	}

	[Test]
	public void DeriveSubkey_StringContext_ValidUTF8_Succeeds()
	{
		Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		RandomGenerator.Fill(masterKey);

		CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 123, "ctx-prod");
		subkey.ShouldNotBeZero();
	}

	[Test]
	public void DeriveSubkey_StringContext_Empty_IsValid()
	{
		Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		RandomGenerator.Fill(masterKey);

		CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 1, string.Empty);
		subkey.ShouldNotBeZero();
	}

	[Test]
	public void DeriveSubkey_StringContext_TooLongUTF8_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
			Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
			CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 0, "áéíóúñ漢字🚀");
		});
	}

	[Test]
	public void DeriveSubkey_StringContext_Null_Throws()
	{
		AssertLite.Throws<ArgumentNullException>(() =>
		{
			Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
			Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
			CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 0, (string)null!);
		});
	}

	[Test]
	public void DeriveSubkey_SameInputs_Deterministic()
	{
		Span<byte> key = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		RandomGenerator.Fill(key);

		Span<byte> sk1 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> sk2 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];

		CryptoKeyDerivation.DeriveSubkey(key, sk1, 77, "abc");
		CryptoKeyDerivation.DeriveSubkey(key, sk2, 77, "abc");

		sk1.ShouldBe(sk2);
	}

	[Test]
	public void DeriveSubkey_DifferentContexts_ProducesDifferentSubkeys()
	{
		Span<byte> key = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		RandomGenerator.Fill(key);

		Span<byte> sk1 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> sk2 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];

		CryptoKeyDerivation.DeriveSubkey(key, sk1, 42, "abc");
		CryptoKeyDerivation.DeriveSubkey(key, sk2, 42, "xyz");

		sk1.ShouldNotBe(sk2);
	}

	[Test]
	public void DeriveSubkey_DifferentIds_ProducesDifferentSubkeys()
	{
		Span<byte> key = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		RandomGenerator.Fill(key);

		Span<byte> sk1 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> sk2 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];

		CryptoKeyDerivation.DeriveSubkey(key, sk1, 1, "ctx1");
		CryptoKeyDerivation.DeriveSubkey(key, sk2, 2, "ctx1");

		sk1.ShouldNotBe(sk2);
	}

	[Test]
	public void GenerateMasterKey_WithSecureMemory_Succeeds()
	{
		using var masterKey = SecureMemory.Create<byte>(CryptoKeyDerivation.MasterKeyLen);
		CryptoKeyDerivation.GenerateMasterKey(masterKey);
		masterKey.ShouldNotBeZero();
	}

	[Test]
	public void DeriveSubkey_WithSecureMemoryAndSpanContext_Succeeds()
	{
		using var masterKey = SecureMemory.Create<byte>(CryptoKeyDerivation.MasterKeyLen);
		using var subkey = SecureMemory.Create<byte>(CryptoKeyDerivation.MinSubkeyLen);
		RandomGenerator.Fill(masterKey);

		Span<byte> context = stackalloc byte[CryptoKeyDerivation.ContextLen];
		context[0] = (byte)'A';

		CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 99, context);
		subkey.ShouldNotBeZero();
	}

	[Test]
	public void DeriveSubkey_WithSecureMemoryAndStringContext_Succeeds()
	{
		using var masterKey = SecureMemory.Create<byte>(CryptoKeyDerivation.MasterKeyLen);
		using var subkey = SecureMemory.Create<byte>(CryptoKeyDerivation.MinSubkeyLen);
		RandomGenerator.Fill(masterKey);

		CryptoKeyDerivation.DeriveSubkey(masterKey, subkey, 321, "devtest");
		subkey.ShouldNotBeZero();
	}

	[Test]
	public void DeriveSubkey_SameInputsWithSecureMemory_Deterministic()
	{
		using var key = SecureMemory.Create<byte>(CryptoKeyDerivation.MasterKeyLen);
		using var sk1 = SecureMemory.Create<byte>(CryptoKeyDerivation.MinSubkeyLen);
		using var sk2 = SecureMemory.Create<byte>(CryptoKeyDerivation.MinSubkeyLen);
		RandomGenerator.Fill(key);

		CryptoKeyDerivation.DeriveSubkey(key, sk1, 88, "ctx8");
		CryptoKeyDerivation.DeriveSubkey(key, sk2, 88, "ctx8");

		sk1.ShouldBe(sk2);
	}

	[Test]
	public void DeriveSubkey_DifferentContextsWithSecureMemory_ProducesDifferentSubkeys()
	{
		using var key = SecureMemory.Create<byte>(CryptoKeyDerivation.MasterKeyLen);
		using var sk1 = SecureMemory.Create<byte>(CryptoKeyDerivation.MinSubkeyLen);
		using var sk2 = SecureMemory.Create<byte>(CryptoKeyDerivation.MinSubkeyLen);
		RandomGenerator.Fill(key);

		CryptoKeyDerivation.DeriveSubkey(key, sk1, 7, "ctxA");
		CryptoKeyDerivation.DeriveSubkey(key, sk2, 7, "ctxB");

		sk1.ShouldNotBe(sk2);
	}

	[Test]
	public void DeriveSubkey_DifferentIdsWithSecureMemory_ProducesDifferentSubkeys()
	{
		using var key = SecureMemory.Create<byte>(CryptoKeyDerivation.MasterKeyLen);
		using var sk1 = SecureMemory.Create<byte>(CryptoKeyDerivation.MinSubkeyLen);
		using var sk2 = SecureMemory.Create<byte>(CryptoKeyDerivation.MinSubkeyLen);
		RandomGenerator.Fill(key);

		CryptoKeyDerivation.DeriveSubkey(key, sk1, 10, "ctx");
		CryptoKeyDerivation.DeriveSubkey(key, sk2, 11, "ctx");

		sk1.ShouldNotBe(sk2);
	}

}
