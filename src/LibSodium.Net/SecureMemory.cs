using LibSodium.Interop;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibSodium
{
	/// <summary>
	/// Provides methods for secure memory management using libsodium.
	/// These methods help protect sensitive data from being swapped to disk or accessed by other processes.
	/// </summary>
	public static class SecureMemory
	{
		/// <summary>
		///	Creates a <see cref="SecureMemory{T}"/> holding the specified number of items of given type 
		/// </summary>
		/// <typeparam name="T">The type of items</typeparam>
		/// <param name="length">The number of items</param>
		/// <returns></returns>
		public static SecureMemory<T> Create<T>(int length) where T : unmanaged
		{
			return new SecureMemory<T>(length);
		}

		/// <summary>
		/// Checks if the given byte buffer is zero.
		/// </summary>
		/// <param name="b">The byte buffer to check.</param>
		/// <returns>True if the byte buffer is zero, false otherwise.</returns>
		public static bool IsZero(ReadOnlySpan<byte> b)
		{
			LibraryInitializer.EnsureInitialized();
			return Native.sodium_is_zero(b, (nuint)b.Length) == 1;
		}

		/// <summary>
		/// Compares two byte buffers for equality in constant time.
		/// </summary>
		/// <param name="b1">First buffer to compare.</param>
		/// <param name="b2">Second buffer to compare.</param>
		/// <returns>True if the buffers are equal, false otherwise.</returns>
		public static bool Equals(ReadOnlySpan<byte> b1, ReadOnlySpan<byte> b2)
		{
			LibraryInitializer.EnsureInitialized();
			if (b1.Length != b2.Length)
			{
				return false;
			}
			return Native.sodium_memcmp(b1, b2, (nuint)b1.Length) == 0;
		}

		/// <summary>
		/// Fills a buffer with zeros, effectively erasing its contents.
		/// </summary>
		/// <param name="buffer">The span of bytes to zero out.</param>
		public static void MemZero(Span<byte> buffer)
		{
			LibraryInitializer.EnsureInitialized();
			Native.sodium_memzero(buffer, (nuint)buffer.Length);
		}

		/// <summary>
		/// Fills a buffer with zeros, effectively erasing its contents.
		/// </summary>
		/// <param name="buffer">The span of bytes to zero out.</param>
		public static void MemZero(byte[] buffer)
		{
			ArgumentNullException.ThrowIfNull(buffer, nameof(buffer));
			MemZero(buffer.AsSpan());
		}

		/// <summary>
		/// Fills a buffer with zeros, effectively erasing its contents.
		/// </summary>
		/// <param name="buffer">The span of bytes to zero out.</param>
		public static void MemZero<T>(Span<T> buffer) where T : unmanaged
		{
			LibraryInitializer.EnsureInitialized();
			Native.sodium_memzero(MemoryMarshal.AsBytes(buffer), (nuint)buffer.Length * (nuint)Unsafe.SizeOf<T>());
		}

		/// <summary>
		/// Fills a buffer with zeros, effectively erasing its contents.
		/// </summary>
		/// <param name="buffer">The span of bytes to zero out.</param>
		public static void MemZero<T>(T[] buffer) where T : unmanaged
		{
			ArgumentNullException.ThrowIfNull(buffer, nameof(buffer));
			MemZero(buffer.AsSpan());
		}

		/// <summary>
		/// Locks an unmanaged memory buffer, preventing it from being swapped to disk.
		/// </summary>
		/// <param name="buffer">The span representing the unmanaged memory to lock.</param>
		/// <exception cref="LibSodiumException">Thrown if locking the memory fails.</exception>
		public static void MemLock(ReadOnlySpan<byte> buffer)
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				if (Native.sodium_mlock((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)), (nuint)buffer.Length) != 0)
				{
					throw new LibSodiumException("Failed to lock memory");
				}
			}
		}

		/// <summary>
		/// Locks an unmanaged memory buffer, preventing it from being swapped to disk.
		/// </summary>
		/// <param name="buffer">The span representing the unmanaged memory to lock.</param>
		/// <exception cref="LibSodiumException">Thrown if locking the memory fails.</exception>
		public static void MemLock<T>(ReadOnlySpan<T> buffer) where T : unmanaged
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				if (Native.sodium_mlock((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)), (nuint)buffer.Length * (nuint)Unsafe.SizeOf<T>()) != 0)
				{
					throw new LibSodiumException("Failed to lock memory");
				}
			}

		}

		/// <summary>
		/// Unlocks an unmanaged memory buffer, allowing it to be swapped to disk if necessary.
		/// </summary>
		/// <param name="buffer">The span of bytes to unlock.</param>
		/// <exception cref="LibSodiumException">Thrown if unlocking the memory fails.</exception>

		public static void MemUnlock(ReadOnlySpan<byte> buffer)
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				if (Native.sodium_munlock((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)), (nuint)buffer.Length) != 0)
				{
					throw new LibSodiumException("Failed to unlock memory");
				}
			}
		}

		/// <summary>
		/// Unlocks an unmanaged memory buffer, allowing it to be swapped to disk if necessary.
		/// </summary>
		/// <param name="buffer">The span of bytes to unlock.</param>
		/// <exception cref="LibSodiumException">Thrown if unlocking the memory fails.</exception>

		public static void MemUnlock<T>(ReadOnlySpan<T> buffer) where T : unmanaged
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				if (Native.sodium_munlock((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)), (nuint)buffer.Length * (nuint)Unsafe.SizeOf<T>()) != 0)
				{
					throw new LibSodiumException("Failed to unlock memory");
				}
			}
		}

		/// <summary>
		/// Allocates a Span of byte buffer of the specified size in unmanaged secure memory.
		/// </summary>
		/// <param name="size">The size of the buffer to allocate in bytes.</param>
		/// <returns>A span of bytes representing the allocated memory.</returns>
		/// <exception cref="LibSodiumException">Thrown if memory allocation fails.</exception>
		internal static Span<byte> Allocate(int size)
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				nint address = Native.sodium_malloc((nuint)size);
				if (address == 0)
				{
					throw new LibSodiumException("Failed to allocate memory");
				}
				return new Span<byte>(address.ToPointer(), size);
			}
		}

		/// <summary>
		/// Allocates an array of the specified type and length in unmanaged secure memory.
		/// </summary>
		/// <typeparam name="T">The type of elements in the array. Must be an unmanaged type.</typeparam>
		/// <param name="length">The number of elements to allocate.</param>
		/// <returns>A span of the specified type representing the allocated memory.</returns>
		/// <exception cref="LibSodiumException">Thrown if memory allocation fails.</exception>

		internal static Span<T> Allocate<T>(int length) where T : unmanaged
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				nint address = Native.sodium_allocarray((nuint)length, (nuint)sizeof(T));
				if (address == 0)
				{
					throw new LibSodiumException("Failed to allocate memory");
				}
				return new Span<T>(address.ToPointer(), length);
			}
		}


		/// <summary>
		/// Frees an unmanaged memory buffer allocated with <see cref="Allocate{T}"/>.
		/// It also fills the memory region with zeros before the deallocation.
		/// WARNING: if you pass a buffer that is not allocated with <see cref="Allocate{T}"/> you will corrupt the process memory.
		/// </summary>
		/// <param name="buffer">The span of bytes representing the memory to free.</param>
		internal static void Free<T>(Span<T> buffer) where T : unmanaged
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				Native.sodium_free((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)));
			}
		}

		/// <summary>
		/// Frees an unmanaged memory buffer allocated with <see cref="Allocate"/>.
		/// It also fills the memory region with zeros before the deallocation.
		/// WARNING: if you pass a buffer that is not allocated with <see cref="Allocate"/> you will corrupt the process memory.
		/// </summary>
		/// <param name="buffer">The span of bytes representing the memory to free.</param>
		internal static void Free(Span<byte> buffer)
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				Native.sodium_free((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)));
			}
		}

		/// <summary>
		/// Marks an unmanaged memory region allocated using <see cref="Allocate"/> as read-only.
		/// </summary>
		/// <param name="buffer">The <see cref="Span{Byte}"/> representing the unmanaged memory region to be marked as read-only.</param>
		/// <returns>The <see cref="ReadOnlySpan{Byte}"/> representing the read-only unmanaged memory region</returns>
		/// <exception cref="LibSodiumException">Thrown if setting the memory protection fails.</exception>

		internal static ReadOnlySpan<byte> ProtectReadOnly(Span<byte> buffer)
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				if (Native.sodium_mprotect_readonly((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer))) != 0)
				{
					throw new LibSodiumException("Failed to set memory to read-only");
				}
			}
			return (ReadOnlySpan<byte>)buffer;
		}


		/// <summary>
		/// Marks an unmanaged memory region allocated using <see cref="Allocate{T}"/> as read-only.
		/// </summary>
		/// <typeparam name="T">The type of elements in the span. Must be an unmanaged type.</typeparam>
		/// <param name="buffer">The <see cref="Span{T}"/> representing the unmanaged memory region to be marked as read-only.</param>
		/// <returns>A <see cref="ReadOnlySpan{T}"/> representing the read-only unmanaged memory region</returns>
		/// <exception cref="LibSodiumException">Thrown if setting the memory protection fails.</exception>

		internal static ReadOnlySpan<T> ProtectReadOnly<T>(Span<T> buffer) where T : unmanaged
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				if (Native.sodium_mprotect_readonly((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer))) != 0)
				{
					throw new LibSodiumException("Failed to set memory to read-only");
				}
			}
			return (ReadOnlySpan<T>)buffer;
		}

		/// <summary>
		/// Marks an unmanaged memory region allocated using <see cref="Allocate"/> as read-write
		/// </summary>
		/// <param name="buffer">The <see cref="Span{Byte}"/> representing the unmanaged memory region to be marked as read-write.</param>
		/// <returns>A <see cref="Span{Byte}"/> representing the writable unmanaged memory region</returns>
		/// <exception cref="LibSodiumException">Thrown if setting the memory protection fails.</exception>
		internal static Span<byte> ProtectReadWrite(ReadOnlySpan<byte> buffer)
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				if (Native.sodium_mprotect_readwrite((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer))) != 0)
				{
					throw new LibSodiumException("Failed to set memory to read-write");
				}
				return new Span<byte>(Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)), buffer.Length);
			}
		}


		/// <summary>
		/// Marks an unmanaged memory region allocated using <see cref="Allocate{T}"/> as read-write
		/// </summary>
		/// <typeparam name="T">The type of elements in the span. Must be an unmanaged type.</typeparam>
		/// <param name="buffer">The <see cref="Span{T}"/> representing the unmanaged memory region to be marked as read-write.</param>
		/// <returns>A <see cref="Span{T}"/> representing the writable unmanaged memory region</returns>
		/// <exception cref="LibSodiumException">Thrown if setting the memory protection fails.</exception>
		internal static Span<T> ProtectReadWrite<T>(ReadOnlySpan<T> buffer) where T : unmanaged
		{
			LibraryInitializer.EnsureInitialized();
			unsafe
			{
				if (Native.sodium_mprotect_readwrite((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer))) != 0)
				{
					throw new LibSodiumException("Failed to set memory to read-write");
				}
				return new Span<T>(Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)), buffer.Length);
			}
		}
	}

	/// <summary>
	/// Provides a secure unmanaged memory buffer for unmanaged types, using libsodium for memory protection.
	/// This class encapsulates secure memory allocation, read-only protection, and zeroing.
	/// </summary>
	/// <typeparam name="T">The unmanaged type of elements in the secure memory buffer.</typeparam>
	public sealed class SecureMemory<T> : IDisposable where T : unmanaged
	{
		internal nint address;

		/// <summary>
		/// Gets the length of the secure unmanaged memory buffer, in number of elements of type <typeparamref name="T"/>.
		/// </summary>
		public int Length { get; private set; }

		/// <summary>
		/// Gets a value indicating whether the object has been disposed.
		/// </summary>
		public bool IsDisposed { get; private set; }

		/// <summary>
		/// Gets a value indicating whether the memory region is read-only.
		/// </summary>
		public bool IsReadOnly { get; private set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="SecureMemory{T}"/> class with the specified length.
		/// </summary>
		/// <param name="length">The number of elements of type <typeparamref name="T"/> to allocate.</param>
		/// <exception cref="LibSodiumException">Thrown if memory allocation fails.</exception>
		public SecureMemory(int length)
		{
			LibraryInitializer.EnsureInitialized();
			address = Native.sodium_allocarray((nuint)length, (nuint)Unsafe.SizeOf<T>());
			if (address == 0)
			{
				throw new LibSodiumException("Failed to allocate memory");
			}
			Length = length;
		}

		/// <summary>
		/// Gets a <see cref="Span{T}"/> representing the secure unmanaged memory buffer.
		/// </summary>
		/// <remarks>
		/// While this method returns a new <see cref="Span{T}"/> instance on each call,
		/// all returned spans represent the same underlying memory region.
		/// Modifications made through one span will be visible through any other span obtained from this instance.
		/// </remarks>
		/// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
		/// <exception cref="InvalidOperationException">Thrown if the memory region is read-only.</exception>
		public Span<T> AsSpan()
		{
			ObjectDisposedException.ThrowIf(IsDisposed, this);
			if (IsReadOnly)
			{
				throw new InvalidOperationException("Memory region is read-only.");
			}
			unsafe
			{
				return new Span<T>((void*)address, Length);
			}
		}

		/// <summary>
		/// Gets a <see cref="ReadOnlySpan{T}"/> representing the secure unmanaged memory buffer.
		/// </summary>
		/// <remarks>
		/// While this method returns a new <see cref="ReadOnlySpan{T}"/> instance on each call,
		/// all returned spans represent the same underlying memory region.
		/// </remarks>
		/// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
		public ReadOnlySpan<T> AsReadOnlySpan()
		{
			ObjectDisposedException.ThrowIf(IsDisposed, this);
			unsafe
			{
				return new ReadOnlySpan<T>((void*)address, Length);
			}
		}

		/// <summary>
		/// Marks the secure unmanaged memory buffer as read-only.
		/// </summary>
		/// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
		/// <exception cref="LibSodiumException">Thrown if setting the memory to read-only fails.</exception>
		public void ProtectReadOnly()
		{
			ObjectDisposedException.ThrowIf(IsDisposed, this);
			if (IsReadOnly) return;
			if (Native.sodium_mprotect_readonly(address) != 0)
			{
				throw new LibSodiumException("Failed to set memory to read-only");
			}
			IsReadOnly = true;
		}

		/// <summary>
		/// Marks the secure unmanaged memory buffer as read-write.
		/// </summary>
		/// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
		/// <exception cref="LibSodiumException">Thrown if setting the memory to read-write fails.</exception>
		public void ProtectReadWrite()
		{
			ObjectDisposedException.ThrowIf(IsDisposed, this);
			if (IsReadOnly == false) return;
			if (Native.sodium_mprotect_readwrite(address) != 0)
			{
				throw new LibSodiumException("Failed to set memory to read-write");
			}
			IsReadOnly = false;
		}

		/// <summary>
		/// Fills the secure unmanaged memory buffer with zeros, effectively erasing its contents.
		/// </summary>
		/// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
		public void MemZero()
		{
			ObjectDisposedException.ThrowIf(IsDisposed, this);
			Native.sodium_memzero(address, (nuint)Length * (nuint)Unsafe.SizeOf<T>());
		}

		/// <summary>
		/// Releases all resources used by the <see cref="SecureMemory{T}"/> object, including the allocated unmanaged secure memory.
		/// </summary>
		public void Dispose()
		{
			if (IsDisposed) return;
			IsDisposed = true;
			Native.sodium_free(address);
			address = 0;
			GC.SuppressFinalize(this);
		}

		/// <summary>
		/// Finalizes an instance of the <see cref="SecureMemory{T}"/> class.
		/// </summary>
		~SecureMemory()
		{
			Dispose();
		}
	}

}
