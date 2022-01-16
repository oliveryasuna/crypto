# Crypto

Time-Based One-Time Password ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)) and HMAC-Based One-Time Password
([RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226)) reference implementations and more.

## Getting Started

### TOTP generation

```java
// Passwords will be 6 digits, change every 30 seconds, and are computed with SHA-1.
TOTP totp = new TOTP(6, Duration.ofSeconds(30L), Keys.generate("HmacSHA1", 160), SHA1.getInstance());

totp.compute(Instant.now());
// OR
totp.compute(Instant.now().toEpochMillis());
```

### HOTP generation

```java
// Passwords will be 6 digits and are computed with SHA-1.
HOTP hotp = new HOTP(6, Keys.generate("HmacSHA1", 160), SHA1.getInstance());

hotp.compute(0L);
```

### HMAC signing

```java
byte[] input = "Hello, World!".getBytes();

// Generate a key.
byte[] key = HMAC.getInstance().generateKey("AES");
// Sign the input using SHA-1.
byte[] tag = HMAC.getInstance().sign(input, key, SHA1.getInstance());

...

// Verify the input later.
boolean valid = HMAC.getInstance().verify(input, tag, key, SHA1.getInstance());
```

### Hashing

Classes: `MD2`, `MD5`, `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA512t224`, `SHA512t256`.

```java
byte[] input = "Hello, World!".getBytes();

// Hash the input using SHA-1.
byte[] hash = SHA1.getInstance().compute(input);
```

### Utility classes' methods

`Keys`:
* `byte[] generate(String algorithm, SecureRandom secureRandom)` – Generates a key, specifying the algorithm and `SecureRandom`.
* `byte[] generate(String algorithm, int keySize)` – Generates a key, specifying the algorithm and key size in bytes.
* `byte[] generate(String algorithm)` – Generates a key, specifying the algorithm.

`Bytes`:
* `byte[] concatenate(byte[] array, byte[]... arrays)` – Concatenates n-arrays.
* `byte[] xor(byte[] array1, byte[] array2)` – XOR operation on two arrays.
* `byte[] toHex(byte[] bytes)` – Converts bytes to hexadecimal bytes.

## License

This code is under the [BSD 3-Clause](LICENSE.txt).

## Sponsoring

If you like my work and want to support it, please consider [sponsoring](https://github.com/sponsors/oliveryasuna) me. Your support helps me make the time to
code great things!
