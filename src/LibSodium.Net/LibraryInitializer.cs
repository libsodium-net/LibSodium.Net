using LibSodium.Interop;
using System.Runtime.CompilerServices;

namespace LibSodium
{
	/// <summary>
	/// Static class that manages the initialization and configuration of libsodium.
	/// </summary>
	public static partial class LibraryInitializer
	{
		private static volatile bool _isInitialized; // Indicates if the library has been initialized.
		private static readonly object initLock = new object(); // Lock object for thread-safe initialization.

		/// <summary>
		/// Ensures that the libsodium library is initialized.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void EnsureInitialized()
		{
			if (_isInitialized) return; // If already initialized, exit.
			lock (initLock) // Lock to ensure thread safety.
			{
				if (_isInitialized) return; // Check again after acquiring the lock.
				InitializeBindings(); // Initialize the bindings.
			}
		}

		/// <summary>
		/// Gets a value indicating whether the library has been initialized
		/// </summary>
		public static bool IsInitialized => _isInitialized;

		/// <summary>
		/// Initializes the libsodium library.
		/// </summary>
		private static void SodiumInit()
		{
			// sodium_init() returns 0 on success, -1 on failure, and 1 if the library had already been initialized.
			if (Native.sodium_init() < 0)
			{
				throw new LibSodiumException("Failed to initialize libsodium."); // Throw exception on failure.
			};
		}

		/// <summary>
		/// Sets a misuse handler for the libsodium library.
		/// </summary>
		/// <param name="handler">The action to handle misuse.</param>
		private static void SetMisuseHandler(Action handler)
		{
			if (Native.sodium_set_misuse_handler(handler) != 0)
			{
				throw new LibSodiumException("Failed to set misuse handler."); // Throw exception on failure.
			};
		}

		/// <summary>
		/// Initializes the bindings and checks for version compatibility.
		/// </summary>
		[MethodImpl(MethodImplOptions.NoInlining)]
		private static void InitializeBindings()
		{
			try
			{
				// Check if the major and minor versions match.
				if (LibraryVersion.GetMajor() != Native.LIBSODIUM_VERSION_MAJOR ||
					LibraryVersion.GetMinor() != Native.LIBSODIUM_VERSION_MINOR)
				{
					string? version = LibraryVersion.GetString();
					throw version != null && version != Native.SODIUM_VERSION_STRING
						? new LibSodiumException($"An error occurred while initializing cryptographic primitives. (Expected libsodium {Native.SODIUM_VERSION_STRING} but found {version}.)")
						: new LibSodiumException("An error occurred while initializing cryptographic primitives: version mismatch");
				}
				SetMisuseHandler(MisuseHandler); // Set the misuse handler.
				SodiumInit(); // Initialize the library.
				_isInitialized = true; // Mark as initialized.
			}
			catch (DllNotFoundException e)
			{
				throw new PlatformNotSupportedException("Could not initialize platform-specific components. libsodium may not be supported on this platform. See https://github.com/ektrah/libsodium-core/blob/master/INSTALL.md for more information.", e);
			}
			catch (BadImageFormatException e)
			{
				throw new PlatformNotSupportedException("Could not initialize platform-specific components. libsodium may not be supported on this platform. See https://github.com/ektrah/libsodium-core/blob/master/INSTALL.md for more information.", e);
			}
		}

		/// <summary>
		/// Handler for misuse detected in the libsodium library.
		/// </summary>
		private static void MisuseHandler()
		{
			throw new LibSodiumException("Misuse detected"); // Throw exception on misuse.
		}
	}
}