namespace FindEntryPoint
{
	internal class Program
	{
#pragma warning disable TUnit0034 // Do not declare a main method
		static void Main(string[] args)
#pragma warning restore TUnit0034 // Do not declare a main method
		{
			Console.WriteLine("Hello, World!");

			var entryPoint = typeof(LibSodium.Tests.AssertLite).Assembly.EntryPoint;

			global::TestingPlatformEntryPoint.Main(args).GetAwaiter().GetResult();
		}
	}
}
