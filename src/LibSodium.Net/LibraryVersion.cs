using LibSodium.Interop;
using System.Runtime.InteropServices;

namespace LibSodium
{
	/// <summary>
	/// Provides methods to retrieve the version information of the Sodium library.
	/// </summary>
	public static partial class LibraryVersion
	{
		/// <summary>
		/// Gets the major version number of the Sodium library.
		/// </summary>
		/// <returns>The major version number as an integer.</returns>
		public static int GetMajor()
		{
			return Native.sodium_library_version_major();
		}

		/// <summary>
		/// Gets the minor version number of the Sodium library.
		/// </summary>
		/// <returns>The minor version number as an integer.</returns>
		public static int GetMinor()
		{
			return Native.sodium_library_version_minor();
		}

		/// <summary>
		/// Gets the version string of the Sodium library.
		/// </summary>
		/// <returns>The version string as a string, or null if the string could not be retrieved.</returns>
		public static string? GetString()
		{
			var ptr = Native.sodium_version_string();
			return Marshal.PtrToStringAnsi(ptr);
		}
	}
}
