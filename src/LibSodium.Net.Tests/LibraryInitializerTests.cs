namespace LibSodium.Tests
{
	public class LibraryInitializerTests
	{
		[Test]
		public void EnsureInitializedTest()
		{
			LibraryInitializer.EnsureInitialized();
			LibraryInitializer.IsInitialized.ShouldBeTrue();
			Interop.Native.sodium_init().ShouldBe(1);
		}
	}
}
