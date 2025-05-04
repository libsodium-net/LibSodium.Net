using TUnit.Assertions.AssertConditions;
using TUnit.Assertions.AssertConditions.Interfaces;
using TUnit.Assertions.AssertionBuilders;
using TUnit.Assertions.Exceptions;

namespace LibSodium.Tests
{
	public static class AssertionExtensions
	{
		public static void ShouldBeSequenceEqualTo(this Span<byte> actual, Span<byte> expected, string? customMessage)
		{
			if (actual.SequenceEqual(expected))
			{
				return;
			}
			var actualHex = Convert.ToHexString(actual);
			var expectedHex = Convert.ToHexString(expected);
			throw new AssertionException($"'Should be sequence equal to' failed. Expected:{expectedHex} but got {actualHex}. {customMessage}");
		}

		public static InvokableValueAssertionBuilder<IEnumerable<TInner>> IsSequenceEqualTo<TInner>(this IValueSource<IEnumerable<TInner>> valueSource, IEnumerable<TInner> expected)
		{
			return valueSource.RegisterAssertion(new SequenceEqualsExpectedValueAssertCondition<IEnumerable<TInner>, TInner>(expected), []);
		}

		public static InvokableValueAssertionBuilder<IEnumerable<TInner>> IsNotSequenceEqualTo<TInner>(this IValueSource<IEnumerable<TInner>> valueSource, IEnumerable<TInner> expected)
		{
			return valueSource.RegisterAssertion(new NotSequenceEqualsExpectedValueAssertCondition<IEnumerable<TInner>, TInner>(expected), []);
		}
	}

	public class SequenceEqualsExpectedValueAssertCondition<TActual, TInner>
		: ExpectedValueAssertCondition<TActual, TActual> where TActual : IEnumerable<TInner>
	{

		public SequenceEqualsExpectedValueAssertCondition(TActual expected) : base(expected)
		{
		}

		protected override string GetExpectation()
			=> $"to be sequence equal to expected value";

		protected override ValueTask<AssertionResult> GetResult(TActual? actualValue, TActual? expectedValue)
		{
			if (actualValue == null && expectedValue == null)
			{
				return AssertionResult.Passed;
			}
			if (actualValue is null || expectedValue is null)
			{
				return AssertionResult.Fail("actual and expected are not sequence equal");
			}
			return AssertionResult.FailIf(!actualValue.SequenceEqual(expectedValue), "actual and expected are not sequence equal");
		}
	}

	public class NotSequenceEqualsExpectedValueAssertCondition<TActual, TInner>
	: ExpectedValueAssertCondition<TActual, TActual> where TActual : IEnumerable<TInner>
	{

		public NotSequenceEqualsExpectedValueAssertCondition(TActual expected) : base(expected)
		{
		}

		protected override string GetExpectation()
			=> $"not to be sequence equal to {base.ExpectedValue}";

		protected override ValueTask<AssertionResult> GetResult(TActual? actualValue, TActual? expectedValue)
		{
			if (actualValue == null && expectedValue == null)
			{
				return AssertionResult.Fail("actual and expected values are both null");
			}

			if (actualValue is null || expectedValue is null)
			{
				return AssertionResult.Passed;
			}
			return AssertionResult.FailIf(actualValue.SequenceEqual(expectedValue), "actual and expected values are sequence equal");
		}
	}
}
