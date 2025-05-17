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

		CryptoKeyDerivation.DeriveSubkey(subkey, 42, context, masterKey);
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
			CryptoKeyDerivation.DeriveSubkey(subkey, 0, context, masterKey);
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
			CryptoKeyDerivation.DeriveSubkey(subkey, 0, context, masterKey);
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
			CryptoKeyDerivation.DeriveSubkey(subkey, 0, context, masterKey);
		});
	}

	[Test]
	public void DeriveSubkey_StringContext_ValidUTF8_Succeeds()
	{
		Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		RandomGenerator.Fill(masterKey);

		CryptoKeyDerivation.DeriveSubkey(subkey, 123, "ctx-prod", masterKey);
		subkey.ShouldNotBeZero();
	}

	[Test]
	public void DeriveSubkey_StringContext_Empty_IsValid()
	{
		Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		RandomGenerator.Fill(masterKey);

		CryptoKeyDerivation.DeriveSubkey(subkey, 1, string.Empty, masterKey);
		subkey.ShouldNotBeZero();
	}

	[Test]
	public void DeriveSubkey_StringContext_TooLongUTF8_Throws()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
			Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
			CryptoKeyDerivation.DeriveSubkey(subkey, 0, "áéíóúñ漢字🚀", masterKey);
		});
	}

	[Test]
	public void DeriveSubkey_StringContext_Null_Throws()
	{
		AssertLite.Throws<ArgumentNullException>(() =>
		{
			Span<byte> subkey = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
			Span<byte> masterKey = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
			CryptoKeyDerivation.DeriveSubkey(subkey, 0, (string) null!, masterKey);
		});
	}

	[Test]
	public void DeriveSubkey_SameInputs_Deterministic()
	{
		Span<byte> key = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		RandomGenerator.Fill(key);

		Span<byte> sk1 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> sk2 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];

		CryptoKeyDerivation.DeriveSubkey(sk1, 77, "abc", key);
		CryptoKeyDerivation.DeriveSubkey(sk2, 77, "abc", key);

		sk1.ShouldBe(sk2);
	}

	[Test]
	public void DeriveSubkey_DifferentContexts_ProducesDifferentSubkeys()
	{
		Span<byte> key = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		RandomGenerator.Fill(key);

		Span<byte> sk1 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> sk2 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];

		CryptoKeyDerivation.DeriveSubkey(sk1, 42, "abc", key);
		CryptoKeyDerivation.DeriveSubkey(sk2, 42, "xyz", key);

		sk1.ShouldNotBe(sk2);
	}

	[Test]
	public void DeriveSubkey_DifferentIds_ProducesDifferentSubkeys()
	{
		Span<byte> key = stackalloc byte[CryptoKeyDerivation.MasterKeyLen];
		RandomGenerator.Fill(key);

		Span<byte> sk1 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];
		Span<byte> sk2 = stackalloc byte[CryptoKeyDerivation.MinSubkeyLen];

		CryptoKeyDerivation.DeriveSubkey(sk1, 1, "ctx1", key);
		CryptoKeyDerivation.DeriveSubkey(sk2, 2, "ctx1", key);

		sk1.ShouldNotBe(sk2);
	}
}
