using LibSodium.Net;

namespace LibSodium.Tests
{
	public class LibraryInitializerTests
	{
		[Test]
		public async Task EnsureInitializedTest()
		{
			LibraryInitializer.EnsureInitialized();
			
			await Assert.That(LibraryInitializer.IsInitialized).IsTrue();
			await Assert.That(LibSodium.Interop.Native.sodium_init()).IsEqualTo(1);
		}
	}
}
