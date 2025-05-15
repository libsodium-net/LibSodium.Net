
using System.Text;
using LibSodium;
namespace LibSodium.Tests;

public class CryptoShortHashTests
{
    private static readonly byte[] FixedKey = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");

    [Test]
    public void ComputeHash_EmptyMessage_KnownKey_CorrectHash()
    {
        var message = ReadOnlySpan<byte>.Empty;
        Span<byte> hash = stackalloc byte[CryptoShortHash.HashLen];
        CryptoShortHash.ComputeHash(hash, message, FixedKey);

        var expected = Convert.FromHexString("310E0EDD47DB6F72");
		hash.ShouldBe(expected);
    }

    [Test]
    public void ComputeHash_ABCMessage_KnownKey_CorrectHash()
    {
        var message = Encoding.UTF8.GetBytes("abc");
        Span<byte> hash = stackalloc byte[CryptoShortHash.HashLen];
        CryptoShortHash.ComputeHash(hash, message, FixedKey);

        var expected = Convert.FromHexString("A50720AA53FABC5D");
		hash.ShouldBe(expected);
    }

    [Test]
    public void ComputeHash_HelloMessage_KnownKey_CorrectHash()
    {
        var message = Encoding.UTF8.GetBytes("hello");
        Span<byte> hash = stackalloc byte[CryptoShortHash.HashLen];
        CryptoShortHash.ComputeHash(hash, message, FixedKey);

        var expected = Convert.FromHexString("81DF675798B34F00");
		hash.ShouldBe(expected);
    }

    [Test]
    public void ComputeHash_DifferentKeys_ProduceDifferentHashes()
    {
        var message = Encoding.UTF8.GetBytes("hello");
        Span<byte> hash1 = stackalloc byte[CryptoShortHash.HashLen];
        Span<byte> hash2 = stackalloc byte[CryptoShortHash.HashLen];

        CryptoShortHash.ComputeHash(hash1, message, FixedKey);

        var otherKey = new byte[CryptoShortHash.KeyLen];
        RandomGenerator.Fill(otherKey);
        CryptoShortHash.ComputeHash(hash2, message, otherKey);

        hash1.ShouldNotBe(hash2);
    }
}
