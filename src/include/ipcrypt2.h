#ifndef ipcrypt2_H
#define ipcrypt2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/** Size of the AES encryption key, in bytes (128 bits). */
#define IPCRYPT_KEYBYTES 16U

/** Size of the encryption tweak, in bytes (64 bits). */
#define IPCRYPT_TWEAKBYTES 8U

/** Maximum length of an IP address string, including the null terminator. */
#define IPCRYPT_MAX_IP_STR_BYTES 46U

/** Size of the binary output for non-deterministic encryption. */
#define IPCRYPT_NDIP_BYTES 24U

/** Size of the hexadecimal output for non-deterministic encryption, including null terminator. */
#define IPCRYPT_NDIP_STR_BYTES (48U + 1U)

/**
 * Encryption context structure.
 * Must be initialized with ipcrypt_init() before use.
 */
typedef struct IPCrypt {
    uint8_t opaque[16U * 11];
} IPCrypt;

/**
 * Initialize the IPCrypt context with a 16-byte secret key.
 *
 * The key must:
 * - Be exactly IPCRYPT_KEYBYTES bytes.
 * - Be secret and randomly generated.
 */
void ipcrypt_init(IPCrypt *ipcrypt, const uint8_t key[IPCRYPT_KEYBYTES]);

/**
 * Securely clear and deinitialize the IPCrypt context.
 *
 * Optional: No heap allocations are used, but this ensures secrets are wiped from memory.
 */
void ipcrypt_deinit(IPCrypt *ipcrypt);

/**
 * Encrypt a 16-byte IP address in-place (format-preserving).
 */
void ipcrypt_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16]);

/**
 * Decrypt a 16-byte IP address in-place (format-preserving).
 */
void ipcrypt_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16]);

/**
 * Encrypt an IP address string (IPv4 or IPv6).
 *
 * Output is a format-preserving string written to encrypted_ip_str.
 * Returns the output length on success, or 0 on error.
 */
size_t ipcrypt_encrypt_ip_str(const IPCrypt *ipcrypt,
                              char encrypted_ip_str[IPCRYPT_MAX_IP_STR_BYTES], const char *ip_str);

/**
 * Decrypt a previously encrypted IP address string.
 *
 * Output is written to ip_str. Returns the output length on success, or 0 on error.
 */
size_t ipcrypt_decrypt_ip_str(const IPCrypt *ipcrypt,
                              char           ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                              const char    *encrypted_ip_str);

/**
 * Non-deterministically encrypt a 16-byte IP address using an 8-byte tweak.
 *
 * Output is written to ndip. `random` must be set to a secure 8-byte random value.
 */
void ipcrypt_nd_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ndip[IPCRYPT_NDIP_BYTES],
                             const uint8_t ip16[16], const uint8_t random[IPCRYPT_TWEAKBYTES]);

/**
 * Decrypt a non-deterministically encrypted 16-byte IP address.
 *
 * Input is ndip, and output is written to ip16.
 */
void ipcrypt_nd_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16],
                             const uint8_t ndip[IPCRYPT_NDIP_BYTES]);

/**
 * Encrypt an IP address string non-deterministically.
 *
 * Output is a hex-encoded zero-terminated string written to encrypted_ip_str.
 *`random` must be an 8-byte random value.
 *
 * Returns the output length, without the null terminator.
 */
size_t ipcrypt_nd_encrypt_ip_str(const IPCrypt *ipcrypt,
                                 char           encrypted_ip_str[IPCRYPT_NDIP_STR_BYTES],
                                 const char    *ip_str,
                                 const uint8_t  random[IPCRYPT_TWEAKBYTES]);

/**
 * Decrypt a hex-encoded IP address string from non-deterministic mode.
 *
 * Output is written to ip_str. Returns the output length on success, or 0 on error.
 */
size_t ipcrypt_nd_decrypt_ip_str(const IPCrypt *ipcrypt,
                                 char           ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                 const char    *encrypted_ip_str);

/**
 * Convert an IP address string (IPv4 or IPv6) to a 16-byte binary representation.
 */
int ipcrypt_str_to_ip16(uint8_t ip16[16], const char *ip_str);

/**
 * Convert a 16-byte binary IP address into a string.
 *
 * Returns the length of the resulting string on success, or 0 on error.
 */
size_t ipcrypt_ip16_to_str(char ip_str[IPCRYPT_MAX_IP_STR_BYTES], const uint8_t ip16[16]);

#ifdef __cplusplus
}
#endif

#endif
