# IPCrypt2

IPCrypt2 is a lightweight C library that encrypts (or “obfuscates”) IP addresses for privacy and security purposes.

It supports both IPv4 and IPv6 addresses, and it can optionally preserve the IP format (so an IP address is still recognized as an IP address after encryption). IPCrypt2 also provides a non-deterministic encryption mode, where encrypting the same address multiple times will yield different ciphertexts.

## Features

- **IPv4 and IPv6 support**  
  Works seamlessly with both IP address formats.

- **Format-Preserving Encryption (FPE)**  
  In “standard” mode, an address is encrypted into another valid IP address. This means that consumers of the data (e.g., logs) still see what appears to be an IP address, but without revealing the original address.

- **Non-Deterministic Encryption**  
  Encrypting the same address twice with the same key can produce different ciphertexts, making it harder for adversaries to detect repeated addresses.

- **Fast and Minimal**  
  Written in C with no external dependencies. Relies on hardware-accelerated AES instructions on modern Intel/AMD (x86_64) and ARM (aarch64) CPUs.

- **Convenient APIs**  
  Functions are provided to encrypt/decrypt in-place (16-byte arrays for addresses) or via string-to-string conversions (e.g., `x.x.x.x` → `y.y.y.y`).

- **No Extra Heap Allocations**  
  Simple usage and easy to integrate into existing projects. Just compile and link.

## Table of Contents

- [IPCrypt2](#ipcrypt2)
  - [Features](#features)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Building with a Traditional C Compiler](#building-with-a-traditional-c-compiler)
  - [Building with Zig](#building-with-zig)
  - [API Overview](#api-overview)
    - [1. `IPCrypt` Context](#1-ipcrypt-context)
    - [2. Initialization and Deinitialization](#2-initialization-and-deinitialization)
    - [3. Format-Preserving Encryption / Decryption](#3-format-preserving-encryption--decryption)
    - [4. Non-Deterministic Encryption / Decryption](#4-non-deterministic-encryption--decryption)
    - [5. Helper Functions](#5-helper-functions)
  - [Examples](#examples)
    - [Format-Preserving Example](#format-preserving-example)
    - [Non-Deterministic Example](#non-deterministic-example)
  - [Security Considerations](#security-considerations)
  - [Limitations and Assumptions](#limitations-and-assumptions)

## Getting Started

1. **Download/Clone** this repository.  
2. **Include** the library’s files (`ipcrypt2.c` and `ipcrypt2.h`) in your project.
3. **Build** and link them with your application, either via a traditional compiler or through Zig.

## Building with a Traditional C Compiler

An example using GCC or Clang might look like:

```bash
# 1. Compile the library
gcc -c -O2 ipcrypt2.c -o ipcrypt2.o

# 2. Compile your application and link with the library object
gcc -O2 myapp.c ipcrypt2.o -o myapp
```

If you are cross-compiling for ARM, make sure your toolchain targets AES-enabled ARM CPUs and sets the appropriate flags.

## Building with Zig

Zig can compile and link C code. You can typically build the project by running:

```bash
zig build -Doptimize=ReleaseFast
```

or

```bash
zig build -Doptimize=ReleaseSmall
```

The resulting library and headers will be placed into the `zig-out` directory.

## API Overview

All user-facing declarations are in **ipcrypt2.h**. Here are the key structures and functions:

### 1. `IPCrypt` Context

```c
typedef struct IPCrypt {
    uint8_t opaque[16 * 11];
} IPCrypt;
```

- Must be initialized via `ipcrypt_init()` with a 16-byte key.
- Optionally, call `ipcrypt_deinit()` to zero out secrets in memory once done.

### 2. Initialization and Deinitialization

```c
void ipcrypt_init(IPCrypt *ipcrypt, const uint8_t key[IPCRYPT_KEYBYTES]);
void ipcrypt_deinit(IPCrypt *ipcrypt);
```

- **Initialization** loads the user-provided AES key and prepares the context.
- **Deinitialization** scrubs sensitive data from memory.

### 3. Format-Preserving Encryption / Decryption

```c
// For 16-byte (binary) representation of IP addresses:
void ipcrypt_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16]);
void ipcrypt_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16]);

// For string-based IP addresses:
size_t ipcrypt_encrypt_ip_str(const IPCrypt *ipcrypt,
                              char encrypted_ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                              const char *ip_str);

size_t ipcrypt_decrypt_ip_str(const IPCrypt *ipcrypt,
                              char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                              const char *encrypted_ip_str);
```

- **`ipcrypt_encrypt_ip16`** / **`ipcrypt_decrypt_ip16`**: In-place encryption/decryption of a 16-byte buffer. An IPv4 address must be placed inside a 16-byte buffer as an IPv4-mapped IPv6.
- **`ipcrypt_encrypt_ip_str`** / **`ipcrypt_decrypt_ip_str`**: Takes an IP string (IPv4 or IPv6), encrypts it as a new IP, and returns the encrypted address as a string. Decryption reverses that process.

### 4. Non-Deterministic Encryption / Decryption

```c
void ipcrypt_nd_encrypt_ip16(const IPCrypt *ipcrypt,
                             uint8_t ndip[IPCRYPT_NDIP_BYTES],
                             const uint8_t ip16[16],
                             const uint8_t random[IPCRYPT_TWEAKBYTES]);

void ipcrypt_nd_decrypt_ip16(const IPCrypt *ipcrypt,
                             uint8_t ip16[16],
                             const uint8_t ndip[IPCRYPT_NDIP_BYTES]);

void ipcrypt_nd_encrypt_ip_str(const IPCrypt *ipcrypt,
                               char encrypted_ip_str[IPCRYPT_NDIP_STR_BYTES],
                               const char *ip_str,
                               const uint8_t random[IPCRYPT_TWEAKBYTES]);

size_t ipcrypt_nd_decrypt_ip_str(const IPCrypt *ipcrypt,
                                 char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                 const char *encrypted_ip_str);
```

- **Non-deterministic** mode takes a random 8-byte tweak (`random[IPCRYPT_TWEAKBYTES]`).  
- Even if you encrypt the same IP multiple times with the same key, encrypted values will not be unique, which helps mitigate traffic analysis or repeated-pattern attacks.
- This mode is *not* format-preserving: the output is 24 bytes (or 48 hex characters).

### 5. Helper Functions

```c
int ipcrypt_str_to_ip16(uint8_t ip16[16], const char *ip_str);
size_t ipcrypt_ip16_to_str(char ip_str[IPCRYPT_MAX_IP_STR_BYTES], const uint8_t ip16[16]);
```

- Convert between string IP addresses and their 16-byte representation.

## Examples

Below are two illustrative examples of using IPCrypt2 in C.

### Format-Preserving Example

```c
#include <stdio.h>
#include <string.h>
#include "ipcrypt2.h"

int main(void) {
    // A 16-byte AES key (for demonstration only; keep yours secret!)
    const uint8_t key[IPCRYPT_KEYBYTES] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // Example IP (could be IPv4 or IPv6)
    const char *original_ip = "192.168.0.100";  // or "::1"

    IPCrypt ctx;
    ipcrypt_init(&ctx, key);

    // Encrypt
    char encrypted_ip[IPCRYPT_MAX_IP_STR_BYTES];
    ipcrypt_encrypt_ip_str(&ctx, encrypted_ip, original_ip);

    // Decrypt
    char decrypted_ip[IPCRYPT_MAX_IP_STR_BYTES];
    ipcrypt_decrypt_ip_str(&ctx, decrypted_ip, encrypted_ip);

    // Print results
    printf("Original IP : %s\n", original_ip);
    printf("Encrypted IP: %s\n", encrypted_ip);
    printf("Decrypted IP: %s\n", decrypted_ip);

    // Clean up
    ipcrypt_deinit(&ctx);
    return 0;
}
```

### Non-Deterministic Example

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "ipcrypt2.h"

int main(void) {
    // A 16-byte AES key
    const uint8_t key[IPCRYPT_KEYBYTES] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
    };
    IPCrypt ctx;
    ipcrypt_init(&ctx, key);

    // We'll generate a random 8-byte tweak
    srand((unsigned)time(NULL));
    uint8_t random_tweak[IPCRYPT_TWEAKBYTES];
    for (int i = 0; i < IPCRYPT_TWEAKBYTES; i++) {
        random_tweak[i] = (uint8_t) rand();
    }

    // Input IP
    const char *original_ip = "2607:f8b0:4005:805::200e"; // example IPv6

    // Encrypt string in non-deterministic mode
    char nd_encrypted_str[IPCRYPT_NDIP_STR_BYTES];
    ipcrypt_nd_encrypt_ip_str(&ctx, nd_encrypted_str, original_ip, random_tweak);

    // Decrypt
    char decrypted_ip[IPCRYPT_MAX_IP_STR_BYTES];
    ipcrypt_nd_decrypt_ip_str(&ctx, decrypted_ip, nd_encrypted_str);

    printf("Original IP : %s\n", original_ip);
    printf("ND-Encrypted: %s\n", nd_encrypted_str);
    printf("Decrypted IP: %s\n", decrypted_ip);

    ipcrypt_deinit(&ctx);
    return 0;
}
```

## Security Considerations

1. **Key Management**  
   - You must provide a secure 16-byte AES key. Protect it and ensure it remains secret.

2. **Tweak Randomness** (for non-deterministic mode)  
   - The 8-byte tweak does not need to be secret; however, it should be random or unique for each encryption to prevent predictable patterns. While collisions may become become a statistical concern after approximately 2^32 encryptions with the same key and IP address, they do not directly expose the IP address without the key.

3. **IP Format Preservation**  
   - In “standard” mode, the library encrypts a 16-byte IP buffer into another 16-byte buffer. After encryption, it *may become a valid IPv6 address even if the original address was IPv4*, or vice versa.  

4. **Not a General Purpose Encryption Library**  
   - This library is specialized for IP address encryption and may not be suitable for arbitrary data encryption.

## Limitations and Assumptions

- **Architecture**: Currently targets x86_64 and ARM (aarch64) with hardware AES.  
- **Dependency on AES Hardware**: It relies heavily on AES CPU instructions for performance.  
- **Format-Preserving**: Standard encryption is format-preserving at the 16-byte level. However, an original IPv4 may decrypt to an IPv6 format (or vice versa) in string form.  

---

**Enjoy using IPCrypt2!** Contributions and bug reports are always welcome. Feel free to open issues or submit pull requests on GitHub to help improve the library.