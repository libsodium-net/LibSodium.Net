namespace LibSodium
{
	/// <summary>
	/// Provides constant values used throughout the Na.Core library.
	/// </summary>
	internal static class Constants
	{
		/// <summary>
		/// The maximum size, in bytes, allowed for stack allocations using <c>stackalloc</c>.
		/// This constant is set to 640 bytes to balance performance and safety.
		/// <para>
		/// The LibSodium.Net library is designed to never exceed this limit for stack allocations.
		/// </para>
		/// <para>
		/// Keeping stack allocations small helps prevent stack overflows and improves performance.
		/// </para>
		/// </summary>
		internal const int MaxStackAlloc = 640;
	}
}
