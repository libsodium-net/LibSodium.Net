using System.Security.Cryptography;

namespace LibSodium
{
	/// <summary>
	/// Represents errors that occur during Sodium operations.
	/// </summary>
	[Serializable]
	public class LibSodiumException : CryptographicException
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="LibSodiumException"/> class.
		/// </summary>
		public LibSodiumException()
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="LibSodiumException"/> class
		/// with a specified error message.
		/// </summary>
		/// <param name="message">The error message that explains the reason for the exception.</param>
		public LibSodiumException(string? message) : base(message)
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="LibSodiumException"/> class
		/// with a specified error message and a reference to the inner exception
		/// that is the cause of this exception.
		/// </summary>
		/// <param name="message">The error message that explains the reason for the exception.</param>
		/// <param name="innerException">The exception that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
		public LibSodiumException(string? message, Exception? innerException) : base(message, innerException)
		{
		}
	}
}
