# 🎲 RandomGenerator

The `RandomGenerator` class in **LibSodium.Net** provides access to cryptographically secure random values. It wraps several functions from libsodium's randombytes API and ensures correct initialization and exception safety.

> 🧂Based on libsodium's [Generating random data](https://doc.libsodium.org/generating_random_data)<br/>
> ℹ️ *See also*: [API Reference for `RandomGenerator`](../api/LibSodium.RandomGenerator.yml)

---

## 🌟 Features

- Generate random 32-bit unsigned integers.
- Generate bounded random integers.
- Fill buffers with secure random bytes.
- Generate deterministic random bytes using a seed.
- Stir or close the RNG engine as needed.

---

## 📋 Getting Random Values

&nbsp;**Get a random 32-bit unsigned integer:** returns a cryptographically secure, uniformly distributed value.

```csharp
uint value = RandomGenerator.GetUInt32();
```



&nbsp; **Get a random value less than an upper bound**: Returns a value in the range `[0, upperBound)`.

```csharp
uint lessThan100 = RandomGenerator.GetUInt32(100);
```


---

## 📋 Filling Buffers

> 🔐 *When dealing with sensitive data (e.g., seeds, key material), prefer using `SecureMemory<byte>` for guarded heap allocations and automatic zeroing.*

&nbsp; **Fill a buffer with unpredictable cryptographic random bytes:**

```csharp
Span<byte> buffer = stackalloc byte[32];
RandomGenerator.Fill(buffer);
```

```csharp
var buffer = new byte[32];
RandomGenerator.Fill(buffer);
```

&nbsp; **


```csharp
using var buffer = SecureMemory.Create<byte>(32);
RandomGenerator.Fill(buffer);
```



&nbsp; **Fill a buffer with deterministic random bytes:**

```csharp
Span<byte> seed = stackalloc byte[RandomGenerator.SeedLen];
RandomGenerator.Fill(seed); // Generate a secure seed

Span<byte> buffer = stackalloc byte[32];
RandomGenerator.FillDeterministic(buffer, seed);
```

```csharp
var seed = new byte[RandomGenerator.SeedLen];
RandomGenerator.Fill(seed); // Generate a secure seed

var buffer = new byte[32];
RandomGenerator.FillDeterministic(buffer, seed);
```

```csharp
using var seed = SecureMemory.Create<byte>(RandomGenerator.SeedLen);
RandomGenerator.Fill(seed); // Generate a secure seed

using var buffer = SecureMemory.Create<byte>(32);
RandomGenerator.FillDeterministic(buffer, seed);
```

The same seed and length will always produce the same output.

> ⚠️ Seed must be exactly `RandomGenerator.SeedLen` bytes long. Otherwise, `ArgumentException` is thrown.

---

## 📋 Stirring and Closing

&nbsp; **Stir the RNG:**

```csharp
RandomGenerator.Stir();
```

This reseeds the RNG, recommended after forking a process or when explicitly needed.

&nbsp; **Close the RNG:**

```csharp
RandomGenerator.Close();
```

Closes the randombytes subsystem. This may be needed in long-running processes or to release resources. Calling it more than once will throw `LibSodiumException`.

---

## ⚠️ Error Handling

- `ArgumentException` — thrown when `FillDeterministic` receives an invalid seed length.
- `LibSodiumException` — thrown when `Close()` fails (e.g., called twice).

---

The `RandomGenerator` API is well-suited for cryptographic use cases and follows safe defaults. It gives you access to high-quality random data and control over deterministic randomness when reproducibility is required.

