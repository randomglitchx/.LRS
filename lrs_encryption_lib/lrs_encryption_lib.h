#ifndef LRS_ENCRYPTION_LIB_H
#define LRS_ENCRYPTION_LIB_H

#include <stdint.h>
#include <sodium.h>

// Magic and version constants
#define MAGIC "LRS"
#define VERSION 2

// Algorithm and KDF identifiers
#define CIPHER_XCHACHA20POLY1305 1
#define KDF_ARGON2ID 1
#define HASH_BLAKE2B 1

// TLV types
#define TLV_KEY_MODE 1
#define TLV_TIMESTAMP 2
#define TLV_FILE_ID 3
#define TLV_COMMENT 4

// Key modes
#define KEY_MODE_PASSWORD 0
#define KEY_MODE_RAW_KEY 1

// TLV structure for extensible header
typedef struct {
    uint8_t type;
    uint8_t length;
    uint8_t value[0]; // Flexible array member
} __attribute__((packed)) tlv_t;

// Header structure for encrypted data with self-describing fields
typedef struct {
    char magic[3];                // "LRS"
    uint8_t version;              // 2
    uint8_t cipher_suite_id;      // 1 = xchacha20poly1305
    uint8_t kdf_id;               // 1 = argon2id
    uint32_t kdf_ops;             // Time cost parameter (network byte order)
    uint32_t kdf_mem_limit_kib;   // Memory cost in KiB (network byte order)
    uint32_t kdf_parallelism;     // Parallelism parameter (network byte order)
    uint8_t salt_len;             // Length of salt (typically 16)
    uint8_t salt[16];             // Random salt for KDF
    uint8_t nonce_len;            // Length of nonce (typically 24)
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]; // 24 bytes
    uint8_t aad_hash_id;          // 1 = blake2b-256, 0 = none
    uint8_t aad_hash_len;         // Length of AAD hash (typically 32 or 0)
    uint8_t aad_hash[32];         // Hash of AAD (paths/doubts)
    uint16_t tlv_len;             // Length of TLV section (network byte order)
    // TLV data would follow here in the actual encrypted data
} header_t;

// Function declarations
int encrypt_blob(const uint8_t* plaintext, size_t pt_len,
                const char* password, const char* aad,
                header_t* header, uint8_t* ciphertext, size_t* ct_len);

int decrypt_blob(const uint8_t* ciphertext, size_t ct_len,
                const char* password, const char* aad,
                header_t* header, uint8_t* plaintext, size_t* pt_len);

int encrypt_blob_ex(const uint8_t* plaintext, size_t pt_len,
                 const void* key_material, int key_mode,
                 const uint8_t* aad, size_t aad_len,
                 header_t* header, uint8_t* tlv_buffer, size_t tlv_buffer_size,
                 uint8_t* ciphertext, size_t* ct_len);

int decrypt_blob_ex(const uint8_t* ciphertext, size_t ct_len,
                 const void* key_material, int key_mode,
                 const uint8_t* aad, size_t aad_len,
                 const header_t* header, const uint8_t* tlv_data, size_t tlv_len,
                 uint8_t* plaintext, size_t* pt_len);

char* encrypt_string(const char* plaintext, const char* password, const char* aad);
char* decrypt_string(const char* ciphertext_hex, const char* password, const char* aad);

int encrypt_file(const char* input_file, const char* output_file, const char* password, const char* aad);
int decrypt_file(const char* input_file, const char* output_file, const char* password, const char* aad);

#endif // LRS_ENCRYPTION_LIB_H