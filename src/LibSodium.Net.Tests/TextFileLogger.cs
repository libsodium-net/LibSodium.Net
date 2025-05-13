using System.Runtime.CompilerServices;

namespace LibSodium.Net.Tests
{
	internal class TextFileLogger
	{
		private static object lockObject = new object();

		public static bool isInitialized = false;

		private static StreamWriter? streamWriter;

		public static void Initialize()
		{
			if (isInitialized)
			{
				return;
			}
			var filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "log.txt");
			Initialize(filePath);
		}

		public static void Initialize(string filePath)
		{
			if (isInitialized)
			{
				return;
			}
			lock (lockObject)
			{
				if (!isInitialized)
				{
					// Initialize the logger with the specified file path
					// For example, you can set up a file writer here
					streamWriter = File.CreateText(filePath);
					isInitialized = true;
				}
			}
		}

		public static void Log(string message)
		{
			if (!isInitialized) return;
			lock (lockObject)
			{
				streamWriter?.WriteLine($"{DateTime.Now}: {message}");
				streamWriter?.Flush();
			}
		}

		public static void Close()
		{
			if (!isInitialized) return;
			lock (lockObject)
			{
				streamWriter?.Close();
				streamWriter = null;
				isInitialized = false;
			}
		}
	}
}
