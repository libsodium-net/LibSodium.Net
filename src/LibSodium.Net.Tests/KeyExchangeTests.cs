using LibSodium.Interop;
using LibSodium.Tests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibSodium.Net.Tests
{
	internal class KeyExchangeTests
	{
		[Test]
		public void Client_And_Server_Functions_Are_Different()
		{
			Span<byte> pk1 = stackalloc byte[Native.CRYPTO_KX_PUBLICKEYBYTES];
			Span<byte> sk1 = stackalloc byte[Native.CRYPTO_KX_SECRETKEYBYTES];
			Span<byte> pk2 = stackalloc byte[Native.CRYPTO_KX_PUBLICKEYBYTES];
			Span<byte> sk2 = stackalloc byte[Native.CRYPTO_KX_SECRETKEYBYTES];

			Span<byte> rx11 = stackalloc byte[Native.CRYPTO_KX_SESSIONKEYBYTES];
			Span<byte> rx12 = stackalloc byte[Native.CRYPTO_KX_SESSIONKEYBYTES];
			Span<byte> tx11 = stackalloc byte[Native.CRYPTO_KX_SESSIONKEYBYTES];
			Span<byte> tx12 = stackalloc byte[Native.CRYPTO_KX_SESSIONKEYBYTES];

			Native.crypto_kx_keypair(pk1, sk1);
			Native.crypto_kx_keypair(pk2, sk2);

			Native.crypto_kx_client_session_keys(rx11, tx11, pk1, sk1, pk2);
			Native.crypto_kx_server_session_keys(rx12, tx12, pk1, sk1, pk2);

			rx11.ShouldNotBe(tx11);
			rx11.ShouldNotBe(rx12);
			rx11.ShouldNotBe(tx12);

			tx12.ShouldNotBe(tx11);
			tx12.ShouldNotBe(rx12);
		}
	}
}
