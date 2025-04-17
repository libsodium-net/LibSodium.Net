using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibSodium
{
	internal class SecureMemoryManager<T> : MemoryManager<T> where T : unmanaged
	{
		private readonly SecureMemory<T> secureMemory;

		public SecureMemoryManager(SecureMemory<T> secureMemory)
		{
			this.secureMemory = secureMemory;
		}

		public override Span<T> GetSpan()
		{
			return secureMemory.AsSpan();
		}

		public override MemoryHandle Pin(int elementIndex = 0)
		{
			if (elementIndex < 0 || elementIndex >= secureMemory.Length)
			{
				throw new ArgumentOutOfRangeException(nameof(elementIndex), "Element index is out of range.");
			}
			unsafe
			{
				return new MemoryHandle((T*)secureMemory.address.ToPointer() + elementIndex);
			}
		}

		public override void Unpin()
		{
		}

		protected override void Dispose(bool disposing)
		{
		}
	}
}
