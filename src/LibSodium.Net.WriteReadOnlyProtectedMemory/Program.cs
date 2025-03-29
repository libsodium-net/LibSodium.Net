namespace LibSodium.WriteReadOnlyProtectedMemory
{
	internal class Program
	{
		static int Main(string[] args)
		{
			var buffer = SecureMemory.Allocate(1024);
			SecureMemory.ProtectReadOnly(buffer);
			// The buffer is now read-only protected, writing to it should throw AccessViolationException
			buffer[0] = 0;
			return 0;
		}
	}
}
