using LibSodium.Net.Tests;
using Microsoft.VisualBasic.FileIO;

namespace LibSodium.Tests
{
	public class LibraryInitializerTests
	{
		[Test]
		public void EnsureInitializedTest()
		{
			TextFileLogger.Initialize();
			TextFileLogger.Log("TUNIT: EnsureInitializedTest started");
			LibraryInitializer.EnsureInitialized();
			LibraryInitializer.IsInitialized.ShouldBeTrue();
			Interop.Native.sodium_init().ShouldBe(1);
		}
	}
}
