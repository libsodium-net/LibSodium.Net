using System.Runtime.InteropServices;
using Shouldly;
using System.Diagnostics;

namespace LibSodium.Tests
{
	public class SecureMemoryTests
	{

		[Test]
		public void NaSecureMemoryT_Allocate_AllocatesMemory_InitializedTo0xdb()
		{
			int length = 16;
			using var secureMemory = SecureMemory.Create<byte>(length);

			secureMemory.Length.ShouldBe(length);
			var actualSpan = secureMemory.AsSpan();

			var expectedByteArray = new byte[length];
			Array.Fill(expectedByteArray, (byte)0xdb);
			actualSpan.ToArray().ShouldBe(expectedByteArray, "The allocated region should be filled with 0xDB bytes");
		}

		[Test]
		public void NaSecureMemoryT_Allocate_WithZeroSize_ShouldNotThrow()
		{
			using var secureMemory = SecureMemory.Create<byte>(0);
			secureMemory.Length.ShouldBe(0);
		}

		[Test]
		public void NaSecureMemoryT_MultipleSpans_ShareSameMemory()
		{
			using var secureMemory = SecureMemory.Create<byte>(10);

			var span1 = secureMemory.AsSpan();
			var span2 = secureMemory.AsSpan();

			span1[0] = 0xFF;
			span2[0].ShouldBe((byte)0xFF);

			span2[5] = 0xAA;
			span1[5].ShouldBe((byte)0xAA);
		}

		[Test]
		public void NaSecureMemoryT_AllocatedMemory_CanBeReadAndWritten()
		{
			using var secureMemory = SecureMemory.Create<byte>(16);

			var actualSpan = secureMemory.AsSpan();
			actualSpan[0] = 0xFF;
			actualSpan[15] = 0xFF;

			actualSpan = secureMemory.AsSpan();
			actualSpan[0].ShouldBe((byte)0xFF);
			actualSpan[15].ShouldBe((byte)0xFF);
		}

		[Test]
		public void NaSecureMemoryT_MemZero_ZerosBuffer()
		{
			using var secureMemory = SecureMemory.Create<byte>(5);
			var span = secureMemory.AsSpan();
			span[0] = 1;
			span[1] = 2;
			span[2] = 3;
			span[3] = 4;
			span[4] = 5;

			secureMemory.MemZero();
			secureMemory.AsSpan().ToArray().ShouldAllBe(b => b == 0);
		}

		[Test]
		public void NaSecureMemoryT_ProtectReadOnly_AllowReading()
		{
			using var secureMemory = SecureMemory.Create<byte>(10);
			secureMemory.ProtectReadOnly();
			secureMemory.IsReadOnly.ShouldBeTrue();

			var actualReadOnlySpan = secureMemory.AsReadOnlySpan();

			actualReadOnlySpan[0].ShouldBe((byte)0xdb);
			actualReadOnlySpan[9].ShouldBe((byte)0xdb);
		}

		[Test]
		public void NaSecureMemoryT_ProtectReadWrite_AllowWriting()
		{
			using var secureMemory = SecureMemory.Create<byte>(10);
			secureMemory.ProtectReadOnly();
			secureMemory.ProtectReadWrite();
			secureMemory.IsReadOnly.ShouldBeFalse();

			var actualSpan = secureMemory.AsSpan();
			actualSpan[0] = 0;
			actualSpan[9] = 0;

			actualSpan = secureMemory.AsSpan();
			actualSpan[0].ShouldBe((byte)0);
			actualSpan[9].ShouldBe((byte)0);
		}

		[Test]
		public void NaSecureMemoryT_Dispose_ReleasesMemory()
		{
			var secureMemory = SecureMemory.Create<byte>(10);
			secureMemory.Dispose();
			secureMemory.IsDisposed.ShouldBeTrue();
			secureMemory.address.ShouldBe(0);
		}

		[Test]
		public void NaSecureMemoryT_Finalizer_ReleasesMemory()
		{
			// Create a NaSecureMemory<byte> object without explicitly disposing it.
			var secureMemory = SecureMemory.Create<byte>(10);

			// Force garbage collection to trigger the finalizer.
			secureMemory = null; // Make the object eligible for garbage collection.
			GC.Collect();
			GC.WaitForPendingFinalizers();

			// At this point, the finalizer should have run and released the memory.
			// We can't directly assert that the memory is released, but we can verify that no exceptions are thrown.
			// This test primarily checks that the finalizer doesn't crash.
			
		}

		[Test]
		public void NaSecureMemoryT_ReadOnlySpan_ThrowsWhenDisposed()
		{
			var secureMemory = SecureMemory.Create<byte>(10);
			secureMemory.Dispose();

			Should.Throw<ObjectDisposedException>(() => secureMemory.AsReadOnlySpan());
		}

		[Test]
		public void NaSecureMemoryT_Span_ThrowsWhenDisposed()
		{
			var secureMemory = SecureMemory.Create<byte>(10);
			secureMemory.Dispose();

			Should.Throw<ObjectDisposedException>(() => secureMemory.AsSpan());
		}

		[Test]
		public void NaSecureMemoryT_Span_ThrowsWhenReadOnly()
		{
			using var secureMemory = SecureMemory.Create<byte>(10);
			secureMemory.ProtectReadOnly();

			Should.Throw<InvalidOperationException>(() => secureMemory.AsSpan());
		}


		[Test]
		public void MemZero_SpanByte_ZerosBuffer()
		{
			byte[] buffer = { 1, 2, 3, 4, 5 };
			SecureMemory.MemZero(buffer.AsSpan());
			buffer.ShouldAllBe(b => b == 0);
		}

		[Test]
		public void MemZero_ByteArray_ZerosBuffer()
		{
			byte[] buffer = { 1, 2, 3, 4, 5 };
			SecureMemory.MemZero(buffer);
			buffer.ShouldAllBe(b => b == 0);
		}

		[Test]
		public void MemZero_SpanLong_ZerosBuffer()
		{
			long[] buffer = { 1, 2, 3, 4, 5 };
			SecureMemory.MemZero(buffer.AsSpan());
			buffer.ShouldAllBe(b => b == 0L);
		}

		[Test]
		public void MemZero_LongArray_ZerosBuffer()
		{
			long[] buffer = { 1, 2, 3, 4, 5 };
			SecureMemory.MemZero(buffer);
			buffer.ShouldAllBe(b => b == 0L);
		}

		[Test]
		public void MemLockAndUnlock_ShouldNotThrow()
		{
			var buffer = SecureMemory.Allocate(1000);
			try
			{
				var holder = new UnmanagedMemorySpanHolder<byte>(buffer);
				Should.NotThrow(() => SecureMemory.MemLock(holder.GetOriginalSpan()));
				Should.NotThrow(() => SecureMemory.MemUnlock(holder.GetOriginalSpan()));
			}
			finally
			{
				SecureMemory.Free(buffer);
			}
		}


		[Test]
		public void Allocate_AllocatesMemory_InitializedTo0xdb()
		{
			int size = 16;
		   
			Span<byte> actualSpan = SecureMemory.Allocate(size);
			try
			{
				
				actualSpan.Length.ShouldBe(size);
				var expectedByteArray = new byte[size];
				Array.Fill(expectedByteArray, (byte) 0xdb);
				actualSpan.ToArray().ShouldBe(expectedByteArray, "The allocated region should be filled with 0xDB bytes");
			}
			finally
			{
				SecureMemory.Free(actualSpan);
			}
		}

		[Test]
		public void Allocate_WithZeroSize_ShouldNotThrow()
		{
			int size = 0;

			Span<byte> actualSpan = SecureMemory.Allocate(size);
			try
			{
				actualSpan.Length.ShouldBe(size);
			}
			finally
			{
				SecureMemory.Free(actualSpan);
			}
		}

		[Test]
		public void Allocate_Longs_WithZeroSize_ShouldNotThrow()
		{
			int size = 0;

			var actualSpan = SecureMemory.Allocate<long>(size);
			try
			{
				actualSpan.Length.ShouldBe(size);
			}
			finally
			{
				SecureMemory.Free(actualSpan);
			}
		}

		[Test]
		public void AllocatedMemory_CanBeReadAndWritten()
		{
			int size = 16;
			Span<byte> actualSpan = SecureMemory.Allocate(size);
			try
			{
				actualSpan[0] = 0xFF;
				actualSpan[0].ShouldBe((byte)0xFF);
				actualSpan[15] = 0xFF;
				actualSpan[15].ShouldBe((byte)0xFF);
			}
			finally
			{
				SecureMemory.Free(actualSpan);
			}
		}

		[Test]
		public void Free_ShouldNotThrow()
		{
			int size = 10;
			Span<byte> span = SecureMemory.Allocate(size);
			SecureMemory.Free(span);
		}

		// This test cannot be implemented, instead of throwing it corrupts memory
		//[Test]
		//public void FreeManagedMemory_ShouldThrow()
		//{
		//	Span<byte> actualSpan = new byte[2048];
		//	try
		//	{
		//		NaSecureMemory.Free(actualSpan);
		//	}
		//	catch (Exception ex)
		//	{
		//		Console.WriteLine(ex.ToString());
		//	}
		//}

		[Test]
		public void Allocate_AllocatesSpanOfLong_InitializedTo0xdb()
		{
			int length = 5;
			Span<long> actualSpanLong = SecureMemory.Allocate<long>(length);
			try
			{
				actualSpanLong.Length.ShouldBe(length);
				var actualSpanByte = MemoryMarshal.AsBytes(actualSpanLong);
				byte[] expectedByteArray = new byte[length * sizeof(long)];
				Array.Fill(expectedByteArray, (byte) 0xDB);
				actualSpanByte.ToArray().ShouldBe(expectedByteArray, "The allocated region should be filled with 0xDB bytes");
			}
			finally
			{
				SecureMemory.Free(actualSpanLong);
			}
		}

		[Test]
		public void ProtectReadOnly_WithSpanByte_AllowReading()
		{
			var buffer = SecureMemory.Allocate(10);
			try
			{
				var readOnlyBuffer = SecureMemory.ProtectReadOnly(buffer);
				readOnlyBuffer[0].ShouldBe((byte)0xdb);
				readOnlyBuffer[9].ShouldBe((byte)0xdb);
			}
			finally
			{
				SecureMemory.Free(buffer);
			}
		}

		[Test]
		public void ProtectReadWrite_WithSpanByte_AllowWriting()
		{
			var buffer = SecureMemory.Allocate(10);
			
			try
			{
				var readOnlyBuffer = SecureMemory.ProtectReadOnly(buffer);
				var writableBuffer = SecureMemory.ProtectReadWrite(readOnlyBuffer);
				writableBuffer[0] = 0;
				writableBuffer[9] = 0;
				writableBuffer[0].ShouldBe((byte)0);
				writableBuffer[9].ShouldBe((byte)0);
			}
			finally
			{
				SecureMemory.Free(buffer);
			}
		}

		[Test]
		public void ProtectReadOnly_WithSpanULong_AllowReading()
		{
			var buffer = SecureMemory.Allocate<ulong>(10);
			try
			{
				var readOnlyBuffer = SecureMemory.ProtectReadOnly(buffer);
				buffer[0].ShouldBe(0xdbdbdbdbdbdbdbdb);
				buffer[9].ShouldBe(0xdbdbdbdbdbdbdbdb);
			}
			finally
			{
				SecureMemory.Free(buffer);
			}
		}

		[Test]
		public void ProtectReadWrite_WithSpanLong_AllowWriting()
		{
			var buffer = SecureMemory.Allocate<long>(10);
			try
			{
				var readOnlyBuffer = SecureMemory.ProtectReadOnly(buffer);
				var writableBuffer = SecureMemory.ProtectReadWrite(readOnlyBuffer);
				writableBuffer[0] = 0;
				writableBuffer[9] = 0;
				writableBuffer[0].ShouldBe(0L);
				writableBuffer[9].ShouldBe(0L);
			}
			finally
			{
				SecureMemory.Free(buffer);
			}
		}


		[Test]
		public void WritingReadOnlyProtectedMemory_ShouldThrowAccessViolationException()
		{
			// AccessViolationException cannot be caught, this is why an external process is needed

			var exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LibSodium.Net.WriteReadOnlyProtectedMemory.exe");
			// Na.WriteReadOnlyProtectedMemory.exe Main method is the following:
			/*
				static int Main(string[] args)
				{
					var buffer = NaSecureMemory.Allocate(1024);
					NaSecureMemory.ProtectReadOnly(buffer);
					// The buffer is now read-only protected, writing to it should throw AccessViolationException
					buffer[0] = 0;
					return 0;
				}
			*/
			var processInfo = new ProcessStartInfo(exePath)
			{
				CreateNoWindow = true,
				UseShellExecute = false,
				RedirectStandardError = true
			};
			using (var process = Process.Start(processInfo))
			{
				process.ShouldNotBeNull();
				process.WaitForExit();
				var standardErrorContent = process.StandardError.ReadToEnd();
				standardErrorContent.ShouldContain("System.AccessViolationException");
				process.ExitCode.ShouldNotBe(0);
			}
		}

		[Test]
		public void ReadingPastAllocatedMemory_ShouldThrowAccessViolationException()
		{
			// AccessViolationException cannot be caught, this is why an external process is needed

			var exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LibSodium.Net.ReadPastAllocatedMemory.exe");
			// Na.ReadPastAllocatedMemory.exe Main method is the following:
			/*
				static int Main(string[] args)
				{
					var buffer = NaSecureMemory.Allocate(1023);
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
						NaSecureMemory.Free(buffer);
					}
				}
			*/
			var processInfo = new ProcessStartInfo(exePath)
			{
				CreateNoWindow = true,
				UseShellExecute = false,
				RedirectStandardError = true
			};

			using (var process = Process.Start(processInfo))
			{
				process.ShouldNotBeNull();
				process.WaitForExit();
				var standardErrorContent = process.StandardError.ReadToEnd();
				standardErrorContent.ShouldContain("System.AccessViolationException");
				process.ExitCode.ShouldNotBe(0);
			}
		}
	}
}