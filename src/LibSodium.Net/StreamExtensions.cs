using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibSodium
{
	internal static class StreamExtensions
	{
		public static int Fill(this Stream stream, byte[] buffer, int offset, int count)
		{
			int totalRead = 0;
			while (totalRead < count)
			{
				int read = stream.Read(buffer, offset + totalRead, count - totalRead);
				if (read == 0) break;
				totalRead += read;
			}
			return totalRead;
		}

		public static async Task<int> FillAsync(this Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
		{
			int totalRead = 0;
			while (totalRead < count)
			{
				int read = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead, ct).ConfigureAwait(false);
				if (read == 0)
					break; // EOF
				totalRead += read;
			}
			return totalRead;
		}
	}
}
