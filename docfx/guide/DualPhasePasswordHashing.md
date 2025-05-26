# 🔐 Dual-Phase Password Hashing

This guide describes a dual-phase password hashing scheme that shifts most of the computational cost to the client. It is useful when the server must handle many concurrent logins and wishes to avoid resource exhaustion.

> 🧂 Based on libsodium's [Password Hashing](https://doc.libsodium.org/password_hashing)
> 👀 See also: [CryptoPasswordHashArgon API Reference](../api/LibSodium.CryptoPasswordHashArgon.yml)

---

## 🌟 Overview

This scheme allows the server to maintain strong control over password registration while shifting the cost of password hashing to the client during login. A deterministic `seed` is derived from the user's email, and both sides agree on the hashing parameters.

* During **registration**, the server derives the `preHash` from the password and stores a fast-verifiable `finalHash`.
* During **login**, the client derives the `preHash` from the password using the same process and sends it to the server.

This reduces computational load on the server at login time while maintaining server-side control at registration.

---

## 📋 What is Stored in the Database

Each user record must contain:

| Field       | Description                           |
| ----------- | ------------------------------------- |
| `email`     | User identifier                       |
| `finalHash` | The result of `HashPassword(preHash)` |

📝 Since the `seed` is derived deterministically using `BLAKE2b(email)`, there is **no need to store it**. It can always be recomputed.

---

## ✨ Registration Flow

During user registration, the **server** is responsible for generating the `preHash`. This guarantees that it was derived from the password using agreed parameters (e.g., Argon2id, high memory and iterations).

Although this step consumes server resources, registration is a relatively infrequent operation compared to login. This ensures both control and quality of the derived hash, avoiding the risk of clients sending weak or invalid `preHash` values.

```csharp
// SERVER-SIDE REGISTRATION (C#)
(string password, string email) = ReceiveRegistrationRequest();
// (Optional) Evaluate password strength here before proceeding
byte[] seed = new byte[CryptoPasswordHashArgon.SaltLen];
CryptoGenericHash.ComputeHash(seed, Encoding.UTF8.GetBytes(email));

byte[] preHash = new byte[32];

CryptoPasswordHashArgon.DeriveKey(
    preHash,
    password,
    seed,
    iterations: CryptoPasswordHashArgon.InteractiveIterations,
    requiredMemoryLen: CryptoPasswordHashArgon.InteractiveMemoryLen);

string finalHash = CryptoPasswordHashArgon.HashPassword(
    preHash,
    iterations: CryptoPasswordHashArgon.MinIterations,
    requiredMemoryLen: CryptoPasswordHashArgon.MinMemoryLen);


StoreUser(email, finalHash);
```

---

## ✨ Login Flow

During login, the client derives the `preHash` from the password and a deterministic `seed` calculated as `BLAKE2b(email)`. The server performs a fast verification of the `preHash` against the stored `finalHash`.

```csharp
// CLIENT-SIDE (C#)
string password = "correct horse battery staple";
byte[] seed = new byte[CryptoPasswordHashArgon.SaltLen];
CryptoGenericHash.ComputeHash(seed, Encoding.UTF8.GetBytes(email));

byte[] preHash = new byte[32];

CryptoPasswordHashArgon.DeriveKey(
    preHash,
    password,
    seed,
    iterations: CryptoPasswordHashArgon.InteractiveIterations,
    requiredMemoryLen: CryptoPasswordHashArgon.InteractiveMemoryLen);

SendToServer(email, preHash);
```

```csharp
// SERVER-SIDE (C#)
(string email, byte[] preHash) = ReceiveLoginAttempt();
string storedHash = GetStoredFinalHash(email);

bool isValid = CryptoPasswordHashArgon.VerifyPassword(storedHash, preHash);
```

📝 The client-side `DeriveKey(...)` call must use high-cost parameters (e.g., `InteractiveIterations`), while the server-side `HashPassword(...)` uses minimal parameters (`MinIterations`, `MinMemoryLen`) for fast verification only.&#x20;

---

## 🔍 Design Rationale

This implementation differs from the scheme proposed in the [libsodium documentation](https://doc.libsodium.org/password_hashing), where the client is always responsible for computing the `preHash`. That design has a key limitation: during registration, the server cannot validate whether the `preHash` was correctly derived. The client could submit arbitrary data as `preHash` with no way for the server to check that strong parameters were used or that the password meets any policy.

By contrast, in this variation:

* The server derives the `preHash` during registration.
* The seed is generated deterministically using keyless `BLAKE2b(email)`, avoiding storage or synchronization.
* During login, the client derives the `preHash` using the same logic.

This ensures the server has full control during registration and avoids the complexity of managing a secret key or exposing a public seed endpoint.

### 🔁 Why Not Use `BLAKE2b(email, key)`?

Using a keyed hash like `BLAKE2b(email, key)` seems more secure at first glance, but it requires exposing a public endpoint to return the seed to the client. Since the client cannot compute it alone, the endpoint must be public, meaning an attacker can access it too. This defeats the purpose of using a keyed hash and adds deployment complexity (key rotation, synchronization).

---

## 📊 Comparison with Libsodium's Original Model

| Aspect                          | Libsodium Documentation           | This Variation                               |
| ------------------------------- | --------------------------------- | -------------------------------------------- |
| `preHash` derivation (register) | Client                            | **Server** — allows password strength checks |
| `preHash` derivation (login)    | Client                            | Client                                       |
| Seed generation                 | `BLAKE2b(email, key)`             | `BLAKE2b(email)` (keyless, stateless)        |
| Seed storage                    | Not stored                        | Not stored (deterministic)                   |
| Seed delivery                   | Requires public endpoint          | Not required                                 |
| Server validates `preHash`?     | ❌ No                              | ✅ Yes — at registration                      |
| Complexity                      | Medium (key management, endpoint) | Low                                          |
| Server login cost               | Low                               | Low                                          |
| Server registration control     | ❌ None                            | ✅ Full                                       |
| Server registration cost        | Low                               | **High** — expensive Argon2id on server      |

---
## 🚨 Preventing DoS in Registration

Since registration requires the server to compute an expensive Argon2id derivation, it is essential to protect this endpoint from abuse. Without mitigations, an attacker could issue a large number of fake registrations to exhaust CPU or memory.

### ✅ Recommended defenses

| Mitigation                         | Purpose                                                             |
| ---------------------------------- | ------------------------------------------------------------------- |
| CAPTCHA                            | Blocks automated/bot-driven registration attempts before they start |
| Rate limiting per IP               | Prevents rapid bursts of expensive registrations                    |


You can combine these strategies depending on your threat model and system constraints. For most public-facing systems, using CAPTCHA and rate limiting is often sufficient.


---

## ⚠️ Security Considerations

### ✅ Pros

* Offloads CPU/memory-intensive hash to the client.
* Reduces server-side DoS risk from mass login attempts.
* Compatible with libsodium.js on the web.

### ❌ Cons

* If `preHash` is intercepted, it can be used to login (it's equivalent to a password).
* If the database is compromised, brute-forcing `preHash` is easier than brute-forcing the original password.

### 🧠 Implications

* Use HTTPS **strictly** to protect `preHash` in transit.
* Treat `preHash` as a password: never store or reuse it elsewhere.
* Consider binding `preHash` to device context or ephemeral session to mitigate token theft.

---

## 📝 Summary

This scheme is **not a security upgrade** over traditional Argon2-on-server. It is a **performance optimization** that trades some security margin for scalability. Only use it if server resource exhaustion is a real concern.

For most applications, prefer the traditional approach unless you:

* Trust the client device.
* Require high throughput authentication.
* Accept the risks of treating `preHash` as a reusable login token.

---

## 👀 See Also

* 🧂 [libsodium password hashing](https://doc.libsodium.org/password_hashing)
* 🧂 [libsodium.js](https://github.com/jedisct1/libsodium.js)
* ℹ️ [API Reference: CryptoPasswordHashArgon](../api/LibSodium.CryptoPasswordHashArgon.yml)
