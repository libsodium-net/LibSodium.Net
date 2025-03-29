using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium.Net
{
	/// <summary>
	/// Holds the pointer and length of an *unmanaged* memory span for later recreation. **Use only with unmanaged memory.**
	/// </summary>
	/// <remarks>
	/// This class stores the pointer and length of an unmanaged memory span, allowing for its later reconstruction.
	/// It is critical to use this class only with spans pointing to unmanaged memory.
	/// Using it with managed or stack-allocated spans will result in undefined behavior and potential memory corruption.
	/// This holder is particularly useful when a span needs to be accessed in asynchronous operations,
	/// lambda expressions, anonymous methods or other contexts with limited scope, such as after awaiting a task.
	/// </remarks>
	/// <typeparam name="T">The unmanaged type of the span elements.</typeparam>
	public unsafe class UnmanagedMemorySpanHolder<T> where T : unmanaged
	{
		private void* pointer;
		private int length;
		private bool isReadOnly;


		/// <summary>
		/// Initializes a new instance of the <see cref="UnmanagedMemorySpanHolder{T}"/> class from a read-only span. **Use only with unmanaged memory.**
		/// </summary>
		/// <param name="span">The read-only span pointing to unmanaged memory.</param>
		/// <exception cref="ArgumentException">Thrown when the span is empty.</exception>

		public UnmanagedMemorySpanHolder(ReadOnlySpan<T> span)
		{
			if (span.IsEmpty)
			{
				throw new ArgumentException("Span cannot be empty.", nameof(span));
			}
			pointer = Unsafe.AsPointer(ref MemoryMarshal.GetReference(span));
			length = span.Length;
			isReadOnly = true;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="UnmanagedMemorySpanHolder{T}"/> class from a writable span. **Use only with unmanaged memory.**
		/// </summary>
		/// <param name="span">The read-only span pointing to unmanaged memory.</param>
		/// <exception cref="ArgumentException">Thrown when the span is empty.</exception>

		public UnmanagedMemorySpanHolder(Span<T> span)
		{
			if (span.IsEmpty)
			{
				throw new ArgumentException("Span cannot be empty.", nameof(span));
			}
			pointer = Unsafe.AsPointer(ref MemoryMarshal.GetReference(span));
			length = span.Length;
			isReadOnly = false;
		}

		/// <summary>
		/// Creates a new <see cref="Span{T}"/> from the held unmanaged memory representing the original <see cref="Span{T}" />
		/// </summary>
		/// <returns>A <see cref="Span{T}"/> representing the original <see cref="Span{T}"/></returns>
		/// <exception cref="InvalidOperationException">The original span was read-only, you cannot get a writable span.</exception>
		public Span<T> GetOriginalSpan()
		{
			if (isReadOnly)
			{
				throw new InvalidOperationException("The original span was read-only, you cannot get a writable span.");
			}
			return new Span<T>(pointer, length);
		}

		/// <summary>
		/// Creates a new <see cref="ReadOnlySpan{T}"/> from the held unmanaged memory representing the original <see cref="ReadOnlySpan{T}"/>.
		/// </summary>
		/// <returns>A <see cref="ReadOnlySpan{T}"/> representing the original <see cref="ReadOnlySpan{T}" /></returns>
		public ReadOnlySpan<T> GetOriginalReadOnlySpan()
		{
			return new ReadOnlySpan<T>(pointer, length);
		}
	}
}
