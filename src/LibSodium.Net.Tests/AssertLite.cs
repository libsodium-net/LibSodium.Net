// AssertLite.cs
// Minimalist, AOT-safe test assertions for LibSodium.Net


using TUnit.Assertions.Exceptions;

namespace LibSodium.Tests;

public static class AssertLite
{

    public static void ShouldBeTrue(this bool expected, string? message = null)
    {
        if (expected == false)
        {
            throw new AssertionException(message ?? "Should be true, but it's not");
        }
    }

    public static void ShouldNotBeNull(this object? value, string? message = null)
	{
		if (value == null)
		{
			throw new AssertionException(message ?? "Should not be null, but it is");
		}
	}

    public static void ShouldContain(this string? actual, string expected, string? message = null)
    {
        if (actual == null || !actual.Contains(expected))
        {
            throw new AssertionException(message ?? $"Should contain '{expected}', but it doesn't");
        }
    }

	public static void ShouldBeFalse(this bool expected, string? message = null)
	{
		if (expected == true)
		{
			throw new AssertionException(message ?? "Should be false, but it's true");
		}
	}

    public static void ShouldBe(this Span<byte> actual, Span<byte> expected, string? message = null)
	{
		if (actual.Length != expected.Length || !actual.SequenceEqual(expected))
		{
			throw new AssertionException($"Should be {HexEncoding.BinToHex(expected)}, but got {HexEncoding.BinToHex(actual)}. {message}");
		}
	}

	public static void ShouldBe(this ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string? message = null)
	{
		if (actual.Length != expected.Length || !actual.SequenceEqual(expected))
		{
			throw new AssertionException($"Should be {HexEncoding.BinToHex(expected)}, but got {HexEncoding.BinToHex(actual)}. {message}");
		}
	}

	public static void ShouldBe(this SecureMemory<byte> actual, SecureMemory<byte> expected, string? message = null)
	{
		actual.AsSpan().ShouldBe(expected.AsSpan(), message);
	}

	public static void ShouldBeZero(this Span<byte> actual, string? message = null)
	{
		if (SecureMemory.IsZero(actual) == false)
		{
			throw new AssertionException($"Should be zero, but got {HexEncoding.BinToHex(actual)}. {message}");
		}
	}

	public static void ShouldBeZero<T>(this Span<T> actual, string? message = null)  where T : unmanaged
	{
		if (SecureMemory.IsZero(actual) == false)
		{
			throw new AssertionException($"Should be zero, but is not. {message}");
		}
	}

	public static void ShouldBeZero<T>(this T[] actual, string? message = null) where T : unmanaged
	{
		if (SecureMemory.IsZero(actual) == false)
		{
			throw new AssertionException($"Should be zero, but is not. {message}");
		}
	}

	public static void ShouldNotBeZero(this Span<byte> actual, string? message = null)
	{
		if (SecureMemory.IsZero(actual))
		{
			throw new AssertionException($"Should not be zero, but it is. {message}");
		}
	}

	public static void ShouldNotBeZero(this SecureMemory<byte> actual, string? message = null)
	{
		if (actual.IsZero())
		{
			throw new AssertionException($"Should not be zero, but it is. {message}");
		}
	}

	public static void ShouldNotBeZero(this byte[] actual, string? message = null)
	{
		if (SecureMemory.IsZero(actual))
		{
			throw new AssertionException($"Should not be zero, but it is. {message}");
		}
	}




	public static void ShouldBeZero(this byte[] actual, string? message = null)
	{
		if (SecureMemory.IsZero(actual) == false)
		{
			throw new AssertionException($"Should be zero, but got {HexEncoding.BinToHex(actual)}. {message}");
		}
	}

	public static void ShouldNotBe(this Span<byte> actual, Span<byte> expected, string? message = null)
	{
		if (actual.Length == expected.Length && actual.SequenceEqual(expected))
		{
			throw new AssertionException($"Should not be {HexEncoding.BinToHex(expected)}, but got {HexEncoding.BinToHex(actual)}. {message}");
		}
	}


	public static void ShouldNotBe(this SecureMemory<byte> actual, SecureMemory<byte> expected, string? message = null)
	{
		actual.AsSpan().ShouldNotBe(expected.AsSpan(), message);
	}

	public static void ShouldNotBe(this byte[] actual, byte[] expected, string? message = null)
	{
		if (actual.Length == expected.Length && actual.SequenceEqual(expected))
		{
			throw new AssertionException($"Should not be {HexEncoding.BinToHex(expected)}, but got {HexEncoding.BinToHex(actual)}. {message}");
		}
	}




	public static void ShouldBe(this byte[] actual, byte[] expected, string? message = null)
    {
		if (actual.Length != expected.Length || !actual.SequenceEqual(expected))
		{
			throw new AssertionException($"Should be {HexEncoding.BinToHex(expected)}, but got {HexEncoding.BinToHex(actual)}. {message}");
		}
	}

	public static void ShouldBe(this int actual, int expected, string? message = null)
	{
		if (actual != expected)
		{
			throw new AssertionException(message ?? $"Should be {expected}, but got {actual}");
		}
	}

	public static void ShouldNotBe(this int actual, int expected, string? message = null)
	{
		if (actual == expected)
		{
			throw new AssertionException(message ?? $"Should be {expected}, but got {actual}");
		}
	}

	public static void ShouldNotBe(this uint actual, uint expected, string? message = null)
	{
		if (actual == expected)
		{
			throw new AssertionException($"Should not be {expected}, but got {actual}. {message}");
		}
	}

	public static void ShouldNotBe(this string? actual, string expected, string? message = null)
	{
		if (actual == expected)
		{
			throw new AssertionException($"{actual} should not be {expected}. {message}");
		}
	}


	public static void ShouldBeLessThan(this int actual, int expected, string? message = null)
    {
        if (actual >= expected)
        {
            throw new AssertionException($"Should be less than {expected}, but got {actual}. {message}");
        }
    }
	public static void ShouldBeLessThan(this uint actual, uint expected, string? message = null)
	{
		if (actual >= expected)
		{
			throw new AssertionException($"Should be less than {expected}, but got {actual}. {message}");
		}
	}

	public static void ShouldBe<T>(this T? actual, T expected, string? message = null) where T : IEquatable<T>
    {
		
        if (actual == null || actual.Equals(expected) == false)
		{
			throw new AssertionException(message ?? $"Should be {expected}, but got {actual}");
		}
	}

    public static void ShouldBeGreaterThanOrEqualTo(this int actual, int expected, string? message = null)
    {
        if (actual < expected)
        {
            throw new AssertionException(message ?? $"Should be greater or equal to {expected}, but got {actual}");
        }
    }

    public static void Throws<TException>(Action action) where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }
		catch (Exception ex)
		{
			throw new AssertionException($"AssertLite.Throws failed. Expected: {typeof(TException).Name}, but got: {ex.GetType().Name}", ex);
		}
		throw new AssertionException($"AssertLite.Throws failed. Expected: {typeof(TException).Name}, but no exception was thrown");
    }

	public static void ShouldStartWith(this string? actual, string expected, string? message = null)
	{
		if (actual == null || !actual.StartsWith(expected))
		{
			throw new AssertionException($"{actual} Should start with '{expected}', but it doesn't. {message}");
		}
	}



	public static async Task ThrowsAsync<TException>(Func<Task> action) where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException)
        {
            return;
        }
        catch (Exception ex)
        {
            throw new AssertionException($"AssertLite.ThrowsAsync failed. Expected: {typeof(TException).Name}, but got: {ex.GetType().Name}", ex);
        }
        throw new AssertionException($"AssertLite.ThrowsAsync failed. Expected: {typeof(TException).Name}, but no exception was thrown");
    }

}
