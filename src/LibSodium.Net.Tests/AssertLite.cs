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

	public static void ShouldBe<T>(this T actual, T expected, string? message = null) where T : IEquatable<T>
    {
        if (!actual.Equals(expected))
		{
			throw new AssertionException(message ?? $"Should be {expected}, but got {actual}");
		}
	}

	public static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new AssertionException($"AssertLite.Equal failed.\nExpected: {expected}\nActual: {actual}");
    }

    public static void NotEqual<T>(T notExpected, T actual)
    {
        if (EqualityComparer<T>.Default.Equals(notExpected, actual))
            throw new AssertionException($"AssertLite.NotEqual failed.\nValue should not be: {actual}");
    }

    public static void True(bool condition, string? message = null)
    {
        if (!condition)
            throw new AssertionException($"AssertLite.True failed. {message ?? string.Empty}");
    }

    public static void False(bool condition, string? message = null)
    {
        if (condition)
            throw new AssertionException($"AssertLite.False failed. {message ?? string.Empty}");
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


	public static void NotNull(object? value)
    {
        if (value is null)
            throw new AssertionException("AssertLite.NotNull failed. Value was null.");
    }

    public static void Null(object? value)
    {
        if (value is not null)
            throw new AssertionException($"AssertLite.Null failed. Value was not null: {value}");
    }
}
