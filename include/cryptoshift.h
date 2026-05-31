#ifndef CRYPTOSHIFT_H
#define CRYPTOSHIFT_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Algorithm identifiers for the C API.
 */
typedef enum CryptoshiftAlgorithm {
  Ed25519 = 1,
  X25519 = 2,
  Rsa2048 = 3,
  Rsa3072 = 4,
  Rsa4096 = 5,
  EcdsaP256 = 6,
  EcdsaP384 = 7,
  Dilithium2 = 10,
  Dilithium3 = 11,
  Dilithium5 = 12,
  Kyber512 = 20,
  Kyber768 = 21,
  Kyber1024 = 22,
} CryptoshiftAlgorithm;

/**
 * Opaque buffer returned to C callers.
 */
typedef struct CryptoshiftBuffer {
  uint8_t *data;
  uintptr_t len;
} CryptoshiftBuffer;

/**
 * Return the library version string (static, do not free).
 */
const char *cryptoshift_version(void);

/**
 * Return the last error message, or null if none.
 */
const char *cryptoshift_last_error(void);

/**
 * Free a buffer previously returned by CryptoShift.
 */
void cryptoshift_buffer_free(struct CryptoshiftBuffer buf);

/**
 * Generate a key pair for `algorithm`. Public and private keys are returned in
 * separate buffers.
 */
int32_t cryptoshift_keygen(enum CryptoshiftAlgorithm algorithm,
                           struct CryptoshiftBuffer *public_key_out,
                           struct CryptoshiftBuffer *private_key_out);

/**
 * Sign a message. `private_key` must match `algorithm`.
 */
int32_t cryptoshift_sign(enum CryptoshiftAlgorithm algorithm,
                         const uint8_t *private_key,
                         uintptr_t private_key_len,
                         const uint8_t *message,
                         uintptr_t message_len,
                         struct CryptoshiftBuffer *signature_out);

/**
 * Verify a signature. Returns 0 if valid, negative on error or invalid signature.
 */
int32_t cryptoshift_verify(enum CryptoshiftAlgorithm algorithm,
                           const uint8_t *public_key,
                           uintptr_t public_key_len,
                           const uint8_t *message,
                           uintptr_t message_len,
                           const uint8_t *signature,
                           uintptr_t signature_len);

/**
 * Encrypt plaintext for a recipient public key (KEM-DEM).
 */
int32_t cryptoshift_encrypt(enum CryptoshiftAlgorithm algorithm,
                            const uint8_t *public_key,
                            uintptr_t public_key_len,
                            const uint8_t *plaintext,
                            uintptr_t plaintext_len,
                            struct CryptoshiftBuffer *ciphertext_out);

/**
 * Decrypt a message with a private key.
 */
int32_t cryptoshift_decrypt(enum CryptoshiftAlgorithm algorithm,
                            const uint8_t *private_key,
                            uintptr_t private_key_len,
                            const uint8_t *ciphertext,
                            uintptr_t ciphertext_len,
                            struct CryptoshiftBuffer *plaintext_out);

/**
 * Scan text for cryptographic usage. `sources_json` is a JSON array of
 * `[{"name": "file.rs", "content": "..."}]` objects.
 */
int32_t cryptoshift_scan_text(const char *sources_json, struct CryptoshiftBuffer *report_json_out);

#endif /* CRYPTOSHIFT_H */
