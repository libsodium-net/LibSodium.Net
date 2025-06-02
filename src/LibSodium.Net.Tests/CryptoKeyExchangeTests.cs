namespace LibSodium.Tests;

public class CryptoKeyExchangeTests
{
	[Test]
	public void GenerateKeyPair_ShouldGenerateValidKeyPair()
	{
		Span<byte> publicKey = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> secretKey = stackalloc byte[CryptoKeyExchange.SecretKeyLen];

		CryptoKeyExchange.GenerateKeyPair(publicKey, secretKey);

		publicKey.ShouldNotBeZero();
		secretKey.ShouldNotBeZero();
		publicKey.ShouldNotBe(secretKey);
	}

	[Test]
	public void GenerateKeyPairDeterministically_ShouldProduceSameKeysFromSameSeed()
	{
		Span<byte> seed = stackalloc byte[CryptoKeyExchange.SeedLen];
		RandomGenerator.Fill(seed);

		Span<byte> publicKey1 = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> secretKey1 = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
		CryptoKeyExchange.GenerateKeyPairDeterministically(publicKey1, secretKey1, seed);

		Span<byte> publicKey2 = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> secretKey2 = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
		CryptoKeyExchange.GenerateKeyPairDeterministically(publicKey2, secretKey2, seed);

		publicKey1.ShouldBe(publicKey2);
		secretKey1.ShouldBe(secretKey2);
	}

	[Test]
	public void DeriveClientAndServerSessionKeys_ShouldDeriveMatchingSessionKeys()
	{
		Span<byte> clientPk = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> clientSk = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
		CryptoKeyExchange.GenerateKeyPair(clientPk, clientSk);

		Span<byte> serverPk = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> serverSk = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
		CryptoKeyExchange.GenerateKeyPair(serverPk, serverSk);

		Span<byte> clientRx = stackalloc byte[CryptoKeyExchange.SessionKeyLen];
		Span<byte> clientTx = stackalloc byte[CryptoKeyExchange.SessionKeyLen];

		CryptoKeyExchange.DeriveClientSessionKeys(clientRx, clientTx, clientPk, clientSk, serverPk);

		Span<byte> serverRx = stackalloc byte[CryptoKeyExchange.SessionKeyLen];
		Span<byte> serverTx = stackalloc byte[CryptoKeyExchange.SessionKeyLen];

		CryptoKeyExchange.DeriveServerSessionKeys(serverRx, serverTx, serverPk, serverSk, clientPk);

		clientTx.ShouldBe(serverRx, "Client's TX key should match Server's RX key.");
		clientRx.ShouldBe(serverTx, "Client's RX key should match Server's TX key.");
	}

	[Test]
	public void DeriveClientSessionKeys_WithInvalidLengths_ShouldThrowArgumentException()
	{
		var invalidBuffer = new byte[10];
		var validBuffer = new byte[CryptoKeyExchange.SessionKeyLen];
		var publicKey = new byte[CryptoKeyExchange.PublicKeyLen];
		var secretKey = new byte[CryptoKeyExchange.SecretKeyLen];

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.DeriveClientSessionKeys(invalidBuffer, validBuffer, publicKey, secretKey, publicKey));

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.DeriveClientSessionKeys(validBuffer, invalidBuffer, publicKey, secretKey, publicKey));
	}

	[Test]
	public void DeriveServerSessionKeys_WithInvalidLengths_ShouldThrowArgumentException()
	{
		var invalidBuffer = new byte[10];
		var validBuffer = new byte[CryptoKeyExchange.SessionKeyLen];
		var publicKey = new byte[CryptoKeyExchange.PublicKeyLen];
		var secretKey = new byte[CryptoKeyExchange.SecretKeyLen];

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.DeriveServerSessionKeys(invalidBuffer, validBuffer, publicKey, secretKey, publicKey));

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.DeriveServerSessionKeys(validBuffer, invalidBuffer, publicKey, secretKey, publicKey));
	}

	[Test]
	public void GenerateKeyPairDeterministically_WithInvalidSeedLength_ShouldThrowArgumentException()
	{
		AssertLite.Throws<ArgumentException>(() =>
		{
			Span<byte> seed = stackalloc byte[CryptoKeyExchange.SeedLen - 1];
			Span<byte> publicKey = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
			Span<byte> secretKey = stackalloc byte[CryptoKeyExchange.SecretKeyLen];
			CryptoKeyExchange.GenerateKeyPairDeterministically(publicKey, secretKey, seed);
		});
	}

	[Test]
	public void GenerateKeyPairDeterministically_WithInvalidKeyLengths_ShouldThrowArgumentException()
	{
		var seed = new byte[CryptoKeyExchange.SeedLen];
		var tooShortPk = new byte[CryptoKeyExchange.PublicKeyLen - 1];
		var tooShortSk = new byte[CryptoKeyExchange.SecretKeyLen - 1];

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.GenerateKeyPairDeterministically(tooShortPk, stackalloc byte[CryptoKeyExchange.SecretKeyLen], seed));

		AssertLite.Throws<ArgumentException>(() =>
			CryptoKeyExchange.GenerateKeyPairDeterministically(stackalloc byte[CryptoKeyExchange.PublicKeyLen], tooShortSk, seed));
	}

	[Test]
	public void GenerateKeyPair_WithSecureMemory_Succeeds()
	{
		Span<byte> pk = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		using var sk = SecureMemory.Create<byte>(CryptoKeyExchange.SecretKeyLen);
		CryptoKeyExchange.GenerateKeyPair(pk, sk);
		pk.ShouldNotBeZero();
		sk.AsSpan().ShouldNotBeZero();
		pk.ShouldNotBe(sk.AsSpan());
	}

	[Test]
	public void GenerateKeyPairDeterministically_WithSecureMemory_Succeeds()
	{
		using var seed = SecureMemory.Create<byte>(CryptoKeyExchange.SeedLen);
		using var sk1 = SecureMemory.Create<byte>(CryptoKeyExchange.SecretKeyLen);
		using var sk2 = SecureMemory.Create<byte>(CryptoKeyExchange.SecretKeyLen);
		Span<byte> pk1 = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		Span<byte> pk2 = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		RandomGenerator.Fill(seed);

		CryptoKeyExchange.GenerateKeyPairDeterministically(pk1, sk1, seed);
		CryptoKeyExchange.GenerateKeyPairDeterministically(pk2, sk2, seed);

		pk1.ShouldBe(pk2);
		sk1.AsSpan().ShouldBe(sk2.AsSpan());
	}

	[Test]
	public void DeriveSessionKeys_WithSecureMemoryInputs_Succeeds()
	{
		Span<byte> clientPk = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		using var clientSk = SecureMemory.Create<byte>(CryptoKeyExchange.SecretKeyLen);
		CryptoKeyExchange.GenerateKeyPair(clientPk, clientSk);

		Span<byte> serverPk = stackalloc byte[CryptoKeyExchange.PublicKeyLen];
		using var serverSk = SecureMemory.Create<byte>(CryptoKeyExchange.SecretKeyLen);
		CryptoKeyExchange.GenerateKeyPair(serverPk, serverSk);

		using var clientRx = SecureMemory.Create<byte>(CryptoKeyExchange.SessionKeyLen);
		using var clientTx = SecureMemory.Create<byte>(CryptoKeyExchange.SessionKeyLen);

		CryptoKeyExchange.DeriveClientSessionKeys(clientRx, clientTx, clientPk, clientSk, serverPk);

		using var serverRx = SecureMemory.Create<byte>(CryptoKeyExchange.SessionKeyLen);
		using var serverTx = SecureMemory.Create<byte>(CryptoKeyExchange.SessionKeyLen);

		CryptoKeyExchange.DeriveServerSessionKeys(serverRx, serverTx, serverPk, serverSk, clientPk);

		clientTx.AsSpan().ShouldBe(serverRx.AsSpan());
		clientRx.AsSpan().ShouldBe(serverTx.AsSpan());
	}

}
