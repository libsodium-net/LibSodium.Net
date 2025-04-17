using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace LibSodium
{
	[StructLayout(LayoutKind.Explicit, Pack = 1, Size = 16)]
	internal unsafe struct CryptoStreamHeader
	{
		internal static byte[] MagicNumber = new byte[] { 114, 34, 60, 212, 35, 173, 181, 201, 177, 90, 187 };

		[FieldOffset(0)]
		public fixed byte Magic[11];

		[FieldOffset(11)]
		public byte Version;

		[FieldOffset(12)]
		private int _chuckSize;

		public int ChunkSize
		{
			get
			{
				if (BitConverter.IsLittleEndian) return _chuckSize;
				return BinaryPrimitives.ReverseEndianness(_chuckSize);
			}
			set
			{
				if (BitConverter.IsLittleEndian) _chuckSize = value;
				else _chuckSize = BinaryPrimitives.ReverseEndianness(value);
			}
		}
	}
}
