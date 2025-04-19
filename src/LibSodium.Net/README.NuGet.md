🔐 LibSodium.Net — Modern cryptography for .NET 8+

Bindings for [libsodium](https://doc.libsodium.org) with a Span-based API.  
Includes authenticated encryption (XChaCha20-Poly1305), streaming authenticated encryption (SecretStream), secure memory handling (SecureMemory), and many more.

Fast, memory-safe, allocation-free. AOT-ready with `LibraryImport`.

📚 Documentation: https://libsodium.net/

```csharp
// XChaCha20Poly1305 — Combined mode, auto-nonce, with AAD
Span<byte> key = stackalloc byte[XChaCha20Poly1305.KeyLen];
RandomGenerator.Fill(key);

var aad = Encoding.UTF8.GetBytes("context");
var data = Encoding.UTF8.GetBytes("Hello");

var ciphertext = new byte[data.Length + XChaCha20Poly1305.MacLen + XChaCha20Poly1305.NonceLen];
XChaCha20Poly1305.Encrypt(ciphertext, data, key, aad: aad);

var decrypted = new byte[data.Length];
XChaCha20Poly1305.Decrypt(decrypted, ciphertext, key, aad: aad);

var isWorking = decrypted.SequenceEqual(data);
Console.WriteLine($"It works: {isWorking}");
```

```csharp
// SecretStream —  Xchacha20-Poly1305 based authenticated encryption for streams
Span<byte> key = stackalloc byte[32];
RandomGenerator.Fill(key);

var helloData = Encoding.UTF8.GetBytes("Hello LibSodium.Net!");

using var plaintextStream = new MemoryStream();
using var ciphertextStream = new MemoryStream();
using var decryptedStream = new MemoryStream();

plaintextStream.Write(helloData);
plaintextStream.Position = 0;

SecretStream.Encrypt(plaintextStream, ciphertextStream, key);
ciphertextStream.Position = 0;
SecretStream.Decrypt(ciphertextStream, decryptedStream, key);
decryptedStream.Position = 0;

var isWorking = decryptedStream.ToArray().SequenceEqual(helloData);

Console.WriteLine($"It works: {isWorking}");
```