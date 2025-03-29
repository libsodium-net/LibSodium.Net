namespace LibSodium.Net
{
	/// <summary>
	/// Represents errors that occur during Sodium operations.
	/// </summary>
	[Serializable]
	public class SodioException : InvalidOperationException
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="SodioException"/> class.
		/// </summary>
		public SodioException()
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="SodioException"/> class
		/// with a specified error message.
		/// </summary>
		/// <param name="message">The error message that explains the reason for the exception.</param>
		public SodioException(string? message) : base(message)
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="SodioException"/> class
		/// with a specified error message and a reference to the inner exception
		/// that is the cause of this exception.
		/// </summary>
		/// <param name="message">The error message that explains the reason for the exception.</param>
		/// <param name="innerException">The exception that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
		public SodioException(string? message, Exception? innerException) : base(message, innerException)
		{
		}
	}
}
