/**
 * IPCrypt2: Lightweight IP Address Encryption Library
 *
 * IPCrypt2 provides simple and efficient encryption and decryption of IP addresses (IPv4 & IPv6).
 * Designed for privacy-preserving network applications, it supports two encryption modes:
 *
 * 1. **Format-Preserving AES Encryption**
 *    - Transforms an IP address into another valid IP address of the same size.
 *    - Useful for logs or systems that expect syntactically correct IPs.
 *
 * 2. **Non-Deterministic AES Encryption (KIASU-BC)**
 *    - Introduces a 64-bit tweak, producing different ciphertexts for the same IP.
 *    - Useful when repeated IPs must remain unlinkable. This mode is not format-preserving.
 *
 * Additional Features:
 * - Built-in string/binary IP conversion helpers.
 * - Optimized for x86_64 and ARM (aarch64) with AES hardware acceleration.
 * - Minimal external dependencies; just compile and link.
 *
 * Limitations:
 * - Only works on platforms with AES-NI (x86_64) or ARM Crypto Extensions (aarch64).
 * - Not intended for general-purpose encryption—IP address only.
 * - Ensure keys are secret and tweak values are random or unique per encryption.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/types.h>

#include "include/ipcrypt2.h"

/** Number of AES rounds. For AES-128, this is 10. */
#define ROUNDS 10

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#if !defined(MSC_VER) || _MSC_VER < 1800
#    define __vectorcall
#endif

#ifdef __aarch64__
#    ifndef __ARM_FEATURE_CRYPTO
#        define __ARM_FEATURE_CRYPTO 1
#    endif
#    ifndef __ARM_FEATURE_AES
#        define __ARM_FEATURE_AES 1
#    endif

#    include <arm_neon.h>

#    ifdef __clang__
/**
 * Enable AES instructions when compiling with Clang.
 */
#        pragma clang attribute push(__attribute__((target("neon,crypto,aes"))), \
                                     apply_to = function)
#    elif defined(__GNUC__)
/**
 * Enable AES and crypto instructions when compiling with GCC.
 */
#        pragma GCC target("+simd+crypto")
#    endif

/**
 * For AArch64, we represent AES blocks using a 128-bit NEON register (uint64x2_t).
 */
typedef uint64x2_t BlockVec;

/**
 * Load 16 bytes from memory into a NEON register.
 */
#    define LOAD128(a) vld1q_u64((const uint64_t *) (const void *) (a))
/**
 * Store 16 bytes from a NEON register into memory.
 */
#    define STORE128(a, b) vst1q_u64((uint64_t *) (void *) (a), (b))
/**
 * Perform one round of AES encryption (no final round) on block_vec with rkey.
 */
#    define AES_XENCRYPT(block_vec, rkey) \
        vreinterpretq_u64_u8(vaesmcq_u8(vaeseq_u8(vreinterpretq_u8_u64(block_vec), rkey)))
/**
 * Perform the final AES encryption round on block_vec with rkey.
 * The final round excludes the MixColumns step.
 */
#    define AES_XENCRYPTLAST(block_vec, rkey) \
        vreinterpretq_u64_u8(vaeseq_u8(vreinterpretq_u8_u64(block_vec), rkey))
/**
 * Perform one round of AES decryption (no final round) on block_vec with rkey.
 */
#    define AES_XDECRYPT(block_vec, rkey) \
        vreinterpretq_u64_u8(vaesimcq_u8(vaesdq_u8(vreinterpretq_u8_u64(block_vec), rkey)))
/**
 * Perform the final AES decryption round on block_vec with rkey.
 * The final round excludes the InverseMixColumns step.
 */
#    define AES_XDECRYPTLAST(block_vec, rkey) \
        vreinterpretq_u64_u8(vaesdq_u8(vreinterpretq_u8_u64(block_vec), rkey))
/**
 * XOR two 128-bit blocks.
 */
#    define XOR128(a, b) veorq_u64((a), (b))
/**
 * XOR three 128-bit blocks.
 */
#    define XOR128_3(a, b, c) veorq_u64(veorq_u64((a), (b)), c)
/**
 * Create a 128-bit register by combining two 64-bit values.
 */
#    define SET64x2(a, b) vsetq_lane_u64((uint64_t) (a), vmovq_n_u64((uint64_t) (b)), 1)
/**
 * Shift left a 128-bit register by b bytes (zero-filling from the right).
 */
#    define BYTESHL128(a, b) vreinterpretq_u64_u8(vextq_s8(vdupq_n_s8(0), (uint8x16_t) a, 16 - (b)))
/**
 * Reorder 32-bit lanes in a 128-bit register according to the indices (a, b, c, d).
 */
#    define SHUFFLE32x4(x, a, b, c, d)                 \
        vreinterpretq_u64_u32(__builtin_shufflevector( \
            vreinterpretq_u32_u64(x), vreinterpretq_u32_u64(x), (a), (b), (c), (d)))
/**
 * Invert an AES round key for decryption.
 */
#    define RKINVERT(rkey) vaesimcq_u8(rkey)
/**
 * Expand the 8-byte tweak into a 128-bit NEON register.
 */
#    define TWEAK_EXPAND(tweak) \
        vreinterpretq_u8_u32(vmovl_u16(vld1_u16((const uint16_t *) (tweak))));

/**
 * Internal function for deriving a subkey using AES key generation instructions.
 * block_vec: the current AES round key block.
 * rc: the round constant.
 */
static inline BlockVec
AES_KEYGEN(BlockVec block_vec, const int rc)
{
    // Perform an AES single round encryption on block_vec with a zero key.
    // This extracts the needed transformation for generating a new round key.
    uint8x16_t a = vaeseq_u8(vreinterpretq_u8_u64(block_vec), vmovq_n_u8(0));
    // Shuffle for the key expansion rotation.
    const uint8x16_t b =
        __builtin_shufflevector(a, a, 4, 1, 14, 11, 1, 14, 11, 4, 12, 9, 6, 3, 9, 6, 3, 12);
    // Combine with round constant.
    const uint64x2_t c = SET64x2((uint64_t) rc << 32, (uint64_t) rc << 32);
    return XOR128(b, c);
}

#elif defined(__x86_64__)

#    ifdef __clang__
/**
 * Enable AES/AVX instructions when compiling with Clang.
 */
#        pragma clang attribute push(__attribute__((target("aes,avx"))), apply_to = function)
#    elif defined(__GNUC__)
/**
 * Enable AES/AVX instructions when compiling with GCC.
 */
#        pragma GCC target("aes,avx")
#    endif

#    include <smmintrin.h>
#    include <tmmintrin.h>
#    include <wmmintrin.h>

/**
 * On x86_64, we represent AES blocks using __m128i.
 */
typedef __m128i BlockVec;

/**
 * Load 16 bytes from memory into an __m128i.
 */
#    define LOAD128(a)                       _mm_loadu_si128((const BlockVec *) (a))
/**
 * Store 16 bytes from an __m128i into memory.
 */
#    define STORE128(a, b)                   _mm_storeu_si128((BlockVec *) (a), (b))
/**
 * Perform a standard AES round (no final) on block_vec with rkey.
 */
#    define AES_ENCRYPT(block_vec, rkey)     _mm_aesenc_si128((block_vec), (rkey))
/**
 * Perform the final AES round (excludes MixColumns) on block_vec with rkey.
 */
#    define AES_ENCRYPTLAST(block_vec, rkey) _mm_aesenclast_si128((block_vec), (rkey))
/**
 * Perform a standard AES decryption round on block_vec with rkey.
 */
#    define AES_DECRYPT(block_vec, rkey)     _mm_aesdec_si128((block_vec), (rkey))
/**
 * Perform the final AES decryption round (excludes InverseMixColumns) on block_vec with rkey.
 */
#    define AES_DECRYPTLAST(block_vec, rkey) _mm_aesdeclast_si128((block_vec), (rkey))
/**
 * Generate an AES subkey for key expansion.
 */
#    define AES_KEYGEN(block_vec, rc)        _mm_aeskeygenassist_si128((block_vec), (rc))
/**
 * XOR two 128-bit blocks.
 */
#    define XOR128(a, b)                     _mm_xor_si128((a), (b))
/**
 * XOR three 128-bit blocks.
 */
#    define XOR128_3(a, b, c)                _mm_xor_si128(_mm_xor_si128((a), (b)), (c))
/**
 * Construct a 128-bit block from two 64-bit values.
 */
#    define SET64x2(a, b)                    _mm_set_epi64x((uint64_t) (a), (uint64_t) (b))
/**
 * Shift a 128-bit block left by b bytes.
 */
#    define BYTESHL128(a, b)                 _mm_slli_si128(a, b)
/**
 * Reorder 32-bit lanes in a 128-bit block.
 */
#    define SHUFFLE32x4(x, a, b, c, d)       _mm_shuffle_epi32((x), _MM_SHUFFLE((d), (c), (b), (a)))
/**
 * Invert an AES round key for decryption.
 */
#    define RKINVERT(rkey)                   _mm_aesimc_si128(rkey)
/**
 * Expand an 8-byte tweak into a 128-bit register.
 */
#    define TWEAK_EXPAND(tweak)              _mm_cvtepu16_epi32(_mm_cvtsi64_si128(*(const int64_t *) (tweak)))
#else
#    error This architecture is not supported yet
#endif

/**
 * KeySchedule is an array of 1 + ROUNDS 128-bit blocks.
 * The first block is the initial round key, followed by ROUNDS subkeys.
 */
typedef BlockVec KeySchedule[1 + ROUNDS];

/**
 * AesState holds the expanded round keys for encryption/decryption.
 */
typedef struct AesState {
    BlockVec rkeys[1 + ROUNDS];
} AesState;

/**
 * expand_key expands a 16-byte AES key into a full set of round keys.
 * st: the AesState structure to be populated.
 * key: a 16-byte AES key.
 */
static void __vectorcall expand_key(AesState *st, const unsigned char key[IPCRYPT_KEYBYTES])
{
    BlockVec *rkeys = st->rkeys;
    BlockVec  t, s;
    size_t    i = 0;

#define EXPAND_KEY(RC)                        \
    rkeys[i++] = t;                           \
    s          = AES_KEYGEN(t, RC);           \
    t          = XOR128(t, BYTESHL128(t, 4)); \
    t          = XOR128(t, BYTESHL128(t, 8)); \
    t          = XOR128(t, SHUFFLE32x4(s, 3, 3, 3, 3));

    // Load the initial 128-bit key from memory.
    t = LOAD128(&key[0]);
    // Repeatedly generate the next round key.
    EXPAND_KEY(0x01);
    EXPAND_KEY(0x02);
    EXPAND_KEY(0x04);
    EXPAND_KEY(0x08);
    EXPAND_KEY(0x10);
    EXPAND_KEY(0x20);
    EXPAND_KEY(0x40);
    EXPAND_KEY(0x80);
    EXPAND_KEY(0x1b);
    EXPAND_KEY(0x36);
    // Store the final key.
    rkeys[i++] = t;
}

/**
 * aes_encrypt encrypts a 16-byte block x in-place using the expanded keys in st.
 */
static void
aes_encrypt(uint8_t x[16], const AesState *st)
{
    const BlockVec *rkeys = st->rkeys;
    BlockVec        t;
    size_t          i;

#ifdef AES_XENCRYPT
    // For AArch64 with AES_XENCRYPT macros.
    t = AES_XENCRYPT(LOAD128(x), rkeys[0]);
    for (i = 1; i < ROUNDS - 1; i++) {
        t = AES_XENCRYPT(t, rkeys[i]);
    }
    t = AES_XENCRYPTLAST(t, rkeys[i]);
    t = XOR128(t, rkeys[ROUNDS]);
#else
    // For x86_64 or a fallback.
    t = XOR128(LOAD128(x), rkeys[0]);
    for (i = 1; i < ROUNDS; i++) {
        t = AES_ENCRYPT(t, rkeys[i]);
    }
    t = AES_ENCRYPTLAST(t, rkeys[ROUNDS]);
#endif
    STORE128(x, t);
}

/**
 * aes_decrypt decrypts a 16-byte block x in-place using the expanded keys in st.
 */
static void
aes_decrypt(uint8_t x[16], const AesState *st)
{
    const BlockVec *rkeys = st->rkeys;
    BlockVec        t;
    size_t          i;

#ifdef AES_XENCRYPT
    // AArch64 path with AES_XDECRYPT.
    t = AES_XDECRYPT(LOAD128(x), rkeys[ROUNDS]);
    for (i = ROUNDS - 1; i > 1; i--) {
        t = AES_XDECRYPT(t, RKINVERT(rkeys[i]));
    }
    t = AES_XDECRYPTLAST(t, RKINVERT(rkeys[1]));
    t = XOR128(t, rkeys[0]);
#else
    // x86_64 path using AES_DECRYPT.
    t = XOR128(LOAD128(x), rkeys[ROUNDS]);
    for (i = ROUNDS - 1; i > 0; i--) {
        t = AES_DECRYPT(t, RKINVERT(rkeys[i]));
    }
    t = AES_DECRYPTLAST(t, rkeys[0]);
#endif
    STORE128(x, t);
}

/**
 * aes_encrypt_with_tweak encrypts a 16-byte block x with an additional 8-byte tweak.
 * The tweak is XORed with each round key.
 */
static void
aes_encrypt_with_tweak(uint8_t x[16], const AesState *st, const uint8_t tweak[IPCRYPT_TWEAKBYTES])
{
    const BlockVec *rkeys       = st->rkeys;
    const BlockVec  tweak_block = TWEAK_EXPAND(tweak);
    BlockVec        t;
    size_t          i;

#ifdef AES_XENCRYPT
    // AArch64 path.
    t = AES_XENCRYPT(LOAD128(x), XOR128(tweak_block, rkeys[0]));
    for (i = 1; i < ROUNDS - 1; i++) {
        t = AES_XENCRYPT(t, XOR128(tweak_block, rkeys[i]));
    }
    t = AES_XENCRYPTLAST(t, XOR128(tweak_block, rkeys[i]));
    t = XOR128(t, XOR128(tweak_block, rkeys[ROUNDS]));
#else
    // x86_64 path.
    t = XOR128_3(LOAD128(x), tweak_block, rkeys[0]);
    for (i = 1; i < ROUNDS; i++) {
        t = AES_ENCRYPT(t, XOR128(tweak_block, rkeys[i]));
    }
    t = AES_ENCRYPTLAST(t, XOR128(tweak_block, rkeys[ROUNDS]));
#endif
    STORE128(x, t);
}

/**
 * aes_decrypt_with_tweak decrypts a 16-byte block x with an additional 8-byte tweak.
 * The same tweak used during encryption must be provided.
 */
static void
aes_decrypt_with_tweak(uint8_t x[16], const AesState *st, const uint8_t tweak[IPCRYPT_TWEAKBYTES])
{
    const BlockVec *rkeys       = st->rkeys;
    const BlockVec  tweak_block = TWEAK_EXPAND(tweak);
    BlockVec        t;
    size_t          i;

#ifdef AES_XENCRYPT
    t = AES_XDECRYPT(LOAD128(x), XOR128(tweak_block, rkeys[ROUNDS]));
    for (i = ROUNDS - 1; i > 1; i--) {
        t = AES_XDECRYPT(t, RKINVERT(XOR128(tweak_block, rkeys[i])));
    }
    t = AES_XDECRYPTLAST(t, RKINVERT(XOR128(tweak_block, rkeys[1])));
    t = XOR128(t, XOR128(tweak_block, rkeys[0]));
#else
    t = XOR128_3(LOAD128(x), tweak_block, rkeys[ROUNDS]);
    for (i = ROUNDS - 1; i > 0; i--) {
        t = AES_DECRYPT(t, RKINVERT(XOR128(tweak_block, rkeys[i])));
    }
    t = AES_DECRYPTLAST(t, XOR128(tweak_block, rkeys[0]));
#endif
    STORE128(x, t);
}

/**
 * bin2hex converts a binary buffer into a lowercase hex string.
 * hex: the destination buffer.
 * hex_maxlen: maximum capacity of hex.
 * bin: source buffer.
 * bin_len: length of bin.
 * Returns NULL on error, or hex on success.
 */
static char *
bin2hex(char *hex, size_t hex_maxlen, const uint8_t *bin, size_t bin_len)
{
    size_t       i = (size_t) 0U;
    unsigned int x;
    int          b;
    int          c;

    // Check buffer limits.
    if (bin_len >= SIZE_MAX / 2 || hex_maxlen <= bin_len * 2U) {
        return NULL;
    }
    // Convert each byte to two hex characters.
    while (i < bin_len) {
        c = bin[i] & 0xf;
        b = bin[i] >> 4;
        x = (unsigned char) (87U + c + (((c - 10U) >> 8) & ~38U)) << 8 |
            (unsigned char) (87U + b + (((b - 10U) >> 8) & ~38U));
        hex[i * 2U] = (char) x;
        x >>= 8;
        hex[i * 2U + 1U] = (char) x;
        i++;
    }
    // Null-terminate the string.
    hex[i * 2U] = 0U;

    return hex;
}

/**
 * hex2bin converts a hex string into a binary buffer.
 * bin: destination buffer.
 * bin_maxlen: capacity of bin.
 * hex: source string.
 * hex_len: length of the hex string.
 * Returns the number of bytes written on success, or 0 on error.
 */
static size_t
hex2bin(uint8_t *bin, size_t bin_maxlen, const char *hex, size_t hex_len)
{
    const size_t bin_len = hex_len / 2U;
    size_t       i;

    // Must have an even length and fit the destination.
    if (hex_len % 2U != 0 || bin_len > bin_maxlen) {
        return 0U;
    }
    for (i = 0; i < bin_len / 2; i++) {
        unsigned char c = (unsigned char) hex[i * 2U];
        unsigned char b = (unsigned char) hex[i * 2U + 1U];
        // Convert from ASCII to nibble.
        if (c >= '0' && c <= '9') {
            c -= '0';
        } else if (c >= 'a' && c <= 'f') {
            c -= 'a' - 10;
        } else {
            return 0U;
        }
        if (b >= '0' && b <= '9') {
            b -= '0';
        } else if (b >= 'a' && b <= 'f') {
            b -= 'a' - 10;
        } else {
            return 0U;
        }
        bin[i] = ((uint8_t) c << 4) | b;
    }
    return bin_len;
}

/**
 * ipcrypt_str_to_ip16 parses an IP address string (IPv4 or IPv6) into a 16-byte buffer ip16.
 * If it detects an IPv4 address, it is stored as an IPv4-mapped IPv6 address.
 * Returns 0 on success, or -1 on failure.
 */
int
ipcrypt_str_to_ip16(uint8_t ip16[16], const char *ip_str)
{
    struct in6_addr addr6;
    struct in_addr  addr4;

    // Try parsing as IPv6.
    if (inet_pton(AF_INET6, ip_str, &addr6) == 1) {
        memcpy(ip16, &addr6, 16);
        return 0;
    }
    // Try parsing as IPv4.
    if (inet_pton(AF_INET, ip_str, &addr4) == 1) {
        memset(ip16, 0, 16);
        ip16[10] = 0xff;
        ip16[11] = 0xff;
        memcpy(ip16 + 12, &addr4, 4);
        return 0;
    }
    return -1; // Parsing failed.
}

/**
 * ipcrypt_ip16_to_str converts a 16-byte buffer ip16 into its string representation (IPv4 or IPv6).
 * If the buffer holds an IPv4-mapped address, it returns an IPv4 string.
 * Returns the length of the resulting string on success, or 0 on error.
 */
size_t
ipcrypt_ip16_to_str(char ip_str[IPCRYPT_MAX_IP_STR_BYTES], const uint8_t ip16[16])
{
    int    is_ipv4_mapped = 1;
    size_t i;

    COMPILER_ASSERT(IPCRYPT_MAX_IP_STR_BYTES >= INET6_ADDRSTRLEN);

    // Check whether it's an IPv4-mapped IPv6 address (::ffff:x.x.x.x).
    for (i = 0; i < 10; i++) {
        if (ip16[i] != 0) {
            is_ipv4_mapped = 0;
            break;
        }
    }
    if (is_ipv4_mapped && (ip16[10] != 0xff || ip16[11] != 0xff)) {
        is_ipv4_mapped = 0;
    }
    // If IPv4-mapped, convert to IPv4 string.
    if (is_ipv4_mapped) {
        struct in_addr addr4;
        memcpy(&addr4, ip16 + 12, 4);
        if (inet_ntop(AF_INET, &addr4, ip_str, INET_ADDRSTRLEN) == NULL) {
            return 0;
        }
    } else {
        // Otherwise, treat as IPv6.
        struct in6_addr addr6;
        memcpy(&addr6, ip16, 16);
        if (inet_ntop(AF_INET6, &addr6, ip_str, INET6_ADDRSTRLEN) == NULL) {
            return 0;
        }
    }
    return strlen(ip_str);
}

/**
 * ipcrypt_init initializes an IPCrypt context with a 16-byte key.
 * Expands the key into round keys and stores them in ipcrypt->opaque.
 */
void
ipcrypt_init(IPCrypt *ipcrypt, const uint8_t key[IPCRYPT_KEYBYTES])
{
    AesState st;

    expand_key(&st, key);
    COMPILER_ASSERT(sizeof ipcrypt->opaque >= sizeof st);
    memcpy(ipcrypt->opaque, &st, sizeof st);
}

/**
 * ipcrypt_deinit clears the IPCrypt context to wipe sensitive data from memory.
 */
void
ipcrypt_deinit(IPCrypt *ipcrypt)
{
#ifdef __STDC_LIB_EXT1__
    memset_s(ipcrypt, sizeof *ipcrypt, 0, sizeof *ipcrypt);
#else
    memset(ipcrypt, 0, sizeof *ipcrypt);
    // Compiler barrier to prevent optimizations from removing memset.
    __asm__ __volatile__("" : : "r"(ipcrypt) : "memory");
#endif
}

/**
 * ipcrypt_encrypt_ip16 performs format-preserving encryption on a 16-byte IP buffer.
 * Encrypted data is stored in-place.
 */
void
ipcrypt_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16])
{
    AesState st;
    memcpy(&st, ipcrypt->opaque, sizeof st);
    aes_encrypt(ip16, &st);
}

/**
 * ipcrypt_decrypt_ip16 performs format-preserving decryption on a 16-byte IP buffer.
 * Decrypted data is stored in-place.
 */
void
ipcrypt_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16])
{
    AesState st;
    memcpy(&st, ipcrypt->opaque, sizeof st);
    aes_decrypt(ip16, &st);
}

/**
 * ipcrypt_encrypt_ip_str encrypts an IP address string (IPv4 or IPv6) in a format-preserving way.
 * The result is another valid IP address string.
 * Returns the length of the encrypted string or 0 on error.
 */
size_t
ipcrypt_encrypt_ip_str(const IPCrypt *ipcrypt, char encrypted_ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                       const char *ip_str)
{
    uint8_t ip16[16];

    ipcrypt_str_to_ip16(ip16, ip_str);
    ipcrypt_encrypt_ip16(ipcrypt, ip16);
    return ipcrypt_ip16_to_str(encrypted_ip_str, ip16);
}

/**
 * ipcrypt_decrypt_ip_str decrypts an encrypted IP address string and restores the original address.
 * Returns the length of the decrypted string or 0 on error.
 */
size_t
ipcrypt_decrypt_ip_str(const IPCrypt *ipcrypt, char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                       const char *encrypted_ip_str)
{
    uint8_t ip16[16];

    memset(ip_str, 0, IPCRYPT_MAX_IP_STR_BYTES);
    ipcrypt_str_to_ip16(ip16, encrypted_ip_str);
    ipcrypt_decrypt_ip16(ipcrypt, ip16);
    return ipcrypt_ip16_to_str(ip_str, ip16);
}

/**
 * ipcrypt_nd_encrypt_ip16 performs non-deterministic encryption of a 16-byte IP.
 * A random 8-byte tweak (random) must be provided.
 * Output is 24 bytes: the tweak + the encrypted IP.
 */
void
ipcrypt_nd_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ndip[IPCRYPT_NDIP_BYTES],
                        const uint8_t ip16[16], const uint8_t random[IPCRYPT_TWEAKBYTES])
{
    AesState st;

    COMPILER_ASSERT(IPCRYPT_NDIP_BYTES == 16 + IPCRYPT_TWEAKBYTES);
    memcpy(&st, ipcrypt->opaque, sizeof st);
    // Copy the tweak into the first 8 bytes.
    memcpy(ndip, random, IPCRYPT_TWEAKBYTES);
    // Copy the IP into the next 16 bytes.
    memcpy(ndip + IPCRYPT_TWEAKBYTES, ip16, 16);
    // Encrypt the IP portion with the tweak.
    aes_encrypt_with_tweak(ndip + IPCRYPT_TWEAKBYTES, &st, random);
}

/**
 * ipcrypt_nd_decrypt_ip16 decrypts a 24-byte (tweak + IP) buffer produced by
 * ipcrypt_nd_encrypt_ip16. The original IP is restored in ip16.
 */
void
ipcrypt_nd_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16],
                        const uint8_t ndip[IPCRYPT_NDIP_BYTES])
{
    AesState st;

    COMPILER_ASSERT(IPCRYPT_NDIP_BYTES == 16 + IPCRYPT_TWEAKBYTES);
    memcpy(&st, ipcrypt->opaque, sizeof st);
    // Copy the IP portion from ndip.
    memcpy(ip16, ndip + IPCRYPT_TWEAKBYTES, 16);
    // Decrypt using the tweak from the first 8 bytes.
    aes_decrypt_with_tweak(ip16, &st, ndip);
}

/**
 * ipcrypt_nd_encrypt_ip_str encrypts an IP address string in non-deterministic mode.
 * The output is a hex-encoded string of length IPCRYPT_NDIP_STR_BYTES (48 hex chars + null
 * terminator). random must be an 8-byte random value.
 */
size_t
ipcrypt_nd_encrypt_ip_str(const IPCrypt *ipcrypt, char encrypted_ip_str[IPCRYPT_NDIP_STR_BYTES],
                          const char *ip_str, const uint8_t random[IPCRYPT_TWEAKBYTES])
{
    uint8_t ip16[16];
    uint8_t ndip[IPCRYPT_NDIP_BYTES];

    COMPILER_ASSERT(IPCRYPT_NDIP_STR_BYTES == IPCRYPT_NDIP_BYTES * 2 + 1);
    // Convert to 16-byte IP.
    ipcrypt_str_to_ip16(ip16, ip_str);
    // Perform non-deterministic encryption.
    ipcrypt_nd_encrypt_ip16(ipcrypt, ndip, ip16, random);
    // Convert the 24-byte ndip to a hex string.
    bin2hex(encrypted_ip_str, IPCRYPT_NDIP_STR_BYTES, ndip, IPCRYPT_NDIP_BYTES);

    return IPCRYPT_NDIP_STR_BYTES - 1;
}

/**
 * ipcrypt_nd_decrypt_ip_str decrypts a hex-encoded string produced by ipcrypt_nd_encrypt_ip_str.
 * The original IP address string is written to ip_str.
 * Returns the length of the resulting IP string on success, or 0 on error.
 */
size_t
ipcrypt_nd_decrypt_ip_str(const IPCrypt *ipcrypt, char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                          const char *encrypted_ip_str)
{
    uint8_t ip16[16];
    uint8_t ndip[IPCRYPT_NDIP_BYTES];
    memset(ip_str, 0, IPCRYPT_MAX_IP_STR_BYTES);
    // Convert the hex string back to a 24-byte buffer.
    if (hex2bin(ndip, sizeof ndip, encrypted_ip_str, strlen(encrypted_ip_str)) != sizeof ndip) {
        return 0;
    }
    // Decrypt the IP.
    ipcrypt_nd_decrypt_ip16(ipcrypt, ip16, ndip);
    // Convert binary IP to string.
    return ipcrypt_ip16_to_str(ip_str, ip16);
}

#ifdef __clang__
#    pragma clang attribute pop
#endif
