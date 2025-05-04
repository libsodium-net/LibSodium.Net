
using System;
using System.Linq;

namespace LibSodium.Tests
{
    public class CryptoBoxTests
    {
        private const int MessageLen = 128;

        [Test]
        public void EncryptAndDecrypt_WithKeypair_ShouldSucceed()
        {
            Span<byte> recipientPublicKey = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> recipientPrivateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
            CryptoBox.GenerateKeypair(recipientPublicKey, recipientPrivateKey);

            Span<byte> senderPublicKey = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> senderPrivateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
            CryptoBox.GenerateKeypair(senderPublicKey, senderPrivateKey);

            byte[] message = RandomBytes(MessageLen);
            byte[] ciphertext = new byte[message.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
            byte[] decrypted = new byte[message.Length];

            var enc = CryptoBox.EncryptWithKeypair(ciphertext, message, recipientPublicKey, senderPrivateKey);
            var dec = CryptoBox.DecryptWithKeypair(decrypted, enc, senderPublicKey, recipientPrivateKey);

            dec.SequenceEqual(message).ShouldBeTrue();
        }

        [Test]
        public void EncryptAndDecrypt_WithSharedKey_ShouldSucceed()
        {
            Span<byte> alicePublicKey = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> alicePrivateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
            Span<byte> bobPublicKey = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> bobPrivateKey = stackalloc byte[CryptoBox.PrivateKeyLen];

            CryptoBox.GenerateKeypair(alicePublicKey, alicePrivateKey);
            CryptoBox.GenerateKeypair(bobPublicKey, bobPrivateKey);

            Span<byte> sharedKey = stackalloc byte[CryptoBox.SharedKeyLen];
            CryptoBox.CalculateSharedKey(sharedKey, bobPublicKey, alicePrivateKey);

            byte[] message = RandomBytes(MessageLen);
            byte[] ciphertext = new byte[message.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
            byte[] decrypted = new byte[message.Length];

            var enc = CryptoBox.EncryptWithSharedKey(ciphertext, message, sharedKey);
            var dec = CryptoBox.DecryptWithSharedKey(decrypted, enc, sharedKey);

            dec.SequenceEqual(message).ShouldBeTrue();
        }

        [Test]
        public void EncryptAndDecrypt_Detached_WithKeypair_ManualNonce()
        {
            Span<byte> recipientPublicKey = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> recipientPrivateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
            CryptoBox.GenerateKeypair(recipientPublicKey, recipientPrivateKey);

            Span<byte> senderPublicKey = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> senderPrivateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
            CryptoBox.GenerateKeypair(senderPublicKey, senderPrivateKey);

            byte[] message = RandomBytes(MessageLen);
            byte[] nonce = RandomBytes(CryptoBox.NonceLen);
            byte[] ciphertext = new byte[message.Length];
            byte[] mac = new byte[CryptoBox.MacLen];
            byte[] decrypted = new byte[message.Length];

            CryptoBox.EncryptWithKeypair(ciphertext, message, recipientPublicKey, senderPrivateKey, mac, nonce);
            CryptoBox.DecryptWithKeypair(decrypted, ciphertext, senderPublicKey, recipientPrivateKey, mac, nonce)
                     .SequenceEqual(message).ShouldBeTrue();
        }

        [Test]
        public void TamperedCiphertext_ShouldThrow()
        {
            Span<byte> recipientPublicKey = stackalloc byte[CryptoBox.PublicKeyLen];
            var recipientPrivateKey = new byte[CryptoBox.PrivateKeyLen];
            CryptoBox.GenerateKeypair(recipientPublicKey, recipientPrivateKey);

            var senderPublicKey = new byte[CryptoBox.PublicKeyLen];
            Span<byte> senderPrivateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
            CryptoBox.GenerateKeypair(senderPublicKey, senderPrivateKey);

            byte[] message = RandomBytes(MessageLen);
            byte[] ciphertext = new byte[message.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
            byte[] decrypted = new byte[message.Length];

            var enc = CryptoBox.EncryptWithKeypair(ciphertext, message, recipientPublicKey, senderPrivateKey);
            enc[^1] ^= 0x01;

            AssertLite.Throws<LibSodiumException>(() =>
                CryptoBox.DecryptWithKeypair(decrypted, ciphertext, senderPublicKey, recipientPrivateKey));
        }

        private static byte[] RandomBytes(int len)
        {
            var buf = new byte[len];
            Random.Shared.NextBytes(buf);
            return buf;
        }


        [Test]
        public void EncryptAndDecrypt_Detached_WithKeypair_AutoNonce()
        {
            Span<byte> recipientPublicKey = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> recipientPrivateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
            CryptoBox.GenerateKeypair(recipientPublicKey, recipientPrivateKey);

            Span<byte> senderPublicKey = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> senderPrivateKey = stackalloc byte[CryptoBox.PrivateKeyLen];
            CryptoBox.GenerateKeypair(senderPublicKey, senderPrivateKey);

            byte[] message = RandomBytes(MessageLen);
            byte[] ciphertext = new byte[message.Length + CryptoBox.NonceLen];
            byte[] mac = new byte[CryptoBox.MacLen];
            byte[] decrypted = new byte[message.Length];

            var enc = CryptoBox.EncryptWithKeypair(ciphertext, message, recipientPublicKey, senderPrivateKey, mac);
            var dec = CryptoBox.DecryptWithKeypair(decrypted, enc, senderPublicKey, recipientPrivateKey, mac);

            dec.SequenceEqual(message).ShouldBeTrue();
        }

        [Test]
        public void EncryptAndDecrypt_Combined_WithSharedKey_ManualNonce()
        {
            Span<byte> pkA = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> skA = stackalloc byte[CryptoBox.PrivateKeyLen];
            Span<byte> pkB = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> skB = stackalloc byte[CryptoBox.PrivateKeyLen];

            CryptoBox.GenerateKeypair(pkA, skA);
            CryptoBox.GenerateKeypair(pkB, skB);

            Span<byte> shared = stackalloc byte[CryptoBox.SharedKeyLen];
            CryptoBox.CalculateSharedKey(shared, pkB, skA);

            byte[] message = RandomBytes(MessageLen);
            byte[] nonce = RandomBytes(CryptoBox.NonceLen);
            byte[] ciphertext = new byte[message.Length + CryptoBox.MacLen];
            byte[] decrypted = new byte[message.Length];

            CryptoBox.EncryptWithSharedKey(ciphertext, message, shared, nonce: nonce);
            CryptoBox.DecryptWithSharedKey(decrypted, ciphertext, shared, nonce: nonce).SequenceEqual(message).ShouldBeTrue();
        }

        [Test]
        public void EncryptAndDecrypt_Detached_WithSharedKey_ManualNonce()
        {
            Span<byte> pkA = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> skA = stackalloc byte[CryptoBox.PrivateKeyLen];
            Span<byte> pkB = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> skB = stackalloc byte[CryptoBox.PrivateKeyLen];

            CryptoBox.GenerateKeypair(pkA, skA);
            CryptoBox.GenerateKeypair(pkB, skB);

            Span<byte> shared = stackalloc byte[CryptoBox.SharedKeyLen];
            CryptoBox.CalculateSharedKey(shared, pkB, skA);

            byte[] message = RandomBytes(MessageLen);
            byte[] nonce = RandomBytes(CryptoBox.NonceLen);
            byte[] ciphertext = new byte[message.Length];
            byte[] mac = new byte[CryptoBox.MacLen];
            byte[] decrypted = new byte[message.Length];

            CryptoBox.EncryptWithSharedKey(ciphertext, message, shared, mac, nonce);
            CryptoBox.DecryptWithSharedKey(decrypted, ciphertext, shared, mac, nonce).SequenceEqual(message).ShouldBeTrue();
        }

        [Test]
        public void EncryptAndDecrypt_Detached_WithSharedKey_AutoNonce()
        {
            Span<byte> pkA = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> skA = stackalloc byte[CryptoBox.PrivateKeyLen];
            Span<byte> pkB = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> skB = stackalloc byte[CryptoBox.PrivateKeyLen];

            CryptoBox.GenerateKeypair(pkA, skA);
            CryptoBox.GenerateKeypair(pkB, skB);

            Span<byte> shared = stackalloc byte[CryptoBox.SharedKeyLen];
            CryptoBox.CalculateSharedKey(shared, pkB, skA);

            byte[] message = RandomBytes(MessageLen);
            byte[] ciphertext = new byte[message.Length + CryptoBox.NonceLen];
            byte[] mac = new byte[CryptoBox.MacLen];
            byte[] decrypted = new byte[message.Length];

            var enc = CryptoBox.EncryptWithSharedKey(ciphertext, message, shared, mac);
            var dec = CryptoBox.DecryptWithSharedKey(decrypted, enc, shared, mac);

            dec.SequenceEqual(message).ShouldBeTrue();
        }


        [Test]
        public void EncryptWithKeypair_TooSmallCiphertext_ShouldThrow()
        {
            var pk = new byte[CryptoBox.PublicKeyLen];
            var sk = new byte[CryptoBox.PrivateKeyLen];
            CryptoBox.GenerateKeypair(pk, sk);

            byte[] message = RandomBytes(64);
            byte[] ciphertext = new byte[message.Length];

            AssertLite.Throws<ArgumentException>(() =>
                CryptoBox.EncryptWithKeypair(ciphertext, message, pk, sk));
        }

        [Test]
        public void DecryptWithKeypair_TooSmallPlaintext_ShouldThrow()
        {
            var pk = new byte[CryptoBox.PublicKeyLen];
            var sk = new byte[CryptoBox.PrivateKeyLen];
            CryptoBox.GenerateKeypair(pk, sk);

            byte[] message = RandomBytes(64);
            byte[] ciphertext = new byte[message.Length + CryptoBox.MacLen + CryptoBox.NonceLen];
            CryptoBox.EncryptWithKeypair(ciphertext, message, pk, sk);

            byte[] tooSmall = new byte[message.Length - 1];

            AssertLite.Throws<ArgumentException>(() =>
                CryptoBox.DecryptWithKeypair(tooSmall, ciphertext, pk, sk));
        }

        [Test]
        public void EncryptWithSharedKey_InvalidMacLength_ShouldThrow()
        {
            var shared = new byte[CryptoBox.SharedKeyLen];
            byte[] message = RandomBytes(64);
            byte[] ciphertext = new byte[message.Length + CryptoBox.NonceLen];
            byte[] mac = new byte[CryptoBox.MacLen - 1];

            AssertLite.Throws<ArgumentException>(() =>
                CryptoBox.EncryptWithSharedKey(ciphertext, message, shared, mac));
        }

        [Test]
        public void EncryptWithSharedKey_InvalidNonceLength_ShouldThrow()
        {
            var shared = new byte[CryptoBox.SharedKeyLen];
            byte[] message = RandomBytes(64);
            byte[] ciphertext = new byte[message.Length];
            byte[] mac = new byte[CryptoBox.MacLen];
            byte[] nonce = new byte[CryptoBox.NonceLen - 1];

            AssertLite.Throws<ArgumentException>(() =>
                CryptoBox.EncryptWithSharedKey(ciphertext, message, shared, mac, nonce));
        }

        [Test]
        public void DecryptWithSharedKey_InvalidSharedKeyLength_ShouldThrow()
        {
            byte[] shared = new byte[CryptoBox.SharedKeyLen - 1];
            byte[] ciphertext = new byte[64 + CryptoBox.MacLen + CryptoBox.NonceLen];
            byte[] plaintext = new byte[64];

            AssertLite.Throws<ArgumentException>(() =>
                CryptoBox.DecryptWithSharedKey(plaintext, ciphertext, shared));
        }

        [Test]
        public void GenerateKeypairDeterministically_ShouldBeDeterministic()
        {
            byte[] seed = RandomBytes(CryptoBox.SeedLen);
            Span<byte> pk1 = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> sk1 = stackalloc byte[CryptoBox.PrivateKeyLen];
            Span<byte> pk2 = stackalloc byte[CryptoBox.PublicKeyLen];
            Span<byte> sk2 = stackalloc byte[CryptoBox.PrivateKeyLen];

            CryptoBox.GenerateKeypairDeterministically(pk1, sk1, seed);
            CryptoBox.GenerateKeypairDeterministically(pk2, sk2, seed);

            pk1.SequenceEqual(pk2).ShouldBeTrue();
            sk1.SequenceEqual(sk2).ShouldBeTrue();
        }

        [Test]
        public void CalculateSharedKey_WithInvalidLengths_ShouldThrow()
        {
            var sharedKey = new byte[CryptoBox.SharedKeyLen];
            var validPk = new byte[CryptoBox.PublicKeyLen];
            var validSk = new byte[CryptoBox.PrivateKeyLen];

            byte[] shortPk = new byte[CryptoBox.PublicKeyLen - 1];
            byte[] shortSk = new byte[CryptoBox.PrivateKeyLen - 1];
            byte[] shortOut = new byte[CryptoBox.SharedKeyLen - 1];

            // sharedKey buffer demasiado corto
            AssertLite.Throws<ArgumentException>(() =>
                CryptoBox.CalculateSharedKey(shortOut, validPk, validSk));

            // publicKey demasiado corto
            AssertLite.Throws<ArgumentException>(() =>
                CryptoBox.CalculateSharedKey(sharedKey, shortPk, validSk));

			// privateKey demasiado corto
			AssertLite.Throws<ArgumentException>(() =>
                CryptoBox.CalculateSharedKey(sharedKey, validPk, shortSk));
        }
    }
}
