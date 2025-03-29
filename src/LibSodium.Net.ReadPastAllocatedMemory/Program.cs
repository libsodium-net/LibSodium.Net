using LibSodium.Net;

namespace LibSodium.ReadPastAllocatedMemory
{
	internal class Program
	{
		static int Main(string[] args)
		{
			var buffer = SecureMemory.Allocate(1023);
			try
			{
				unsafe
				{
					fixed (byte* ptr = buffer)
					{
						// reading past allocated memory should throw AccessViolationException
						var pastByte = ptr[1023];
					}
				}
				return 0;
			}
			finally
			{
				SecureMemory.Free(buffer);
			}
		}
	}
}
