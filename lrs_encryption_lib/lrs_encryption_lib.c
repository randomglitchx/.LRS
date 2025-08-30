#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>

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

// Add TLV data to a buffer
size_t add_tlv(uint8_t *buffer, size_t max_size, uint8_t type, const uint8_t *value, uint8_t length) {
    if (max_size < 2 + length) {
        return 0; // Not enough space
    }
    
    buffer[0] = type;
    buffer[1] = length;
    memcpy(buffer + 2, value, length);
    
    return 2 + length;
}

// Find TLV data in a buffer
const uint8_t *find_tlv(const uint8_t *buffer, size_t size, uint8_t type, uint8_t *length) {
    size_t pos = 0;
    
    while (pos + 2 <= size) {
        uint8_t tlv_type = buffer[pos];
        uint8_t tlv_length = buffer[pos + 1];
        
        if (pos + 2 + tlv_length > size) {
            break; // Invalid TLV or buffer too small
        }
        
        if (tlv_type == type) {
            if (length) *length = tlv_length;
            return buffer + pos + 2;
        }
        
        pos += 2 + tlv_length;
    }
    
    return NULL; // TLV not found
}

// Derive key using Argon2id (password mode)
int derive_key_argon2id(const char *pwd, const uint8_t salt[16],
                       uint32_t mem_limit_kib, uint32_t ops, uint32_t parallel,
                       uint8_t out_key[32]) {
    // Convert memory limit from KiB to bytes
    unsigned long long mem = (unsigned long long)mem_limit_kib * 1024ULL;
    
    return crypto_pwhash(out_key, 32, pwd, strlen(pwd), salt,
        ops,
        mem,
        crypto_pwhash_ALG_ARGON2ID13);
}

// Derive key from raw key material (raw key mode)
int derive_key_from_raw(const uint32_t *raw_key, size_t raw_key_len, uint8_t out_key[32]) {
    // Convert uint32_t array to bytes in big-endian format
    size_t bytes_len = raw_key_len * sizeof(uint32_t);
    uint8_t *bytes = (uint8_t*)malloc(bytes_len);
    if (!bytes) return -1;
    
    for (size_t i = 0; i < raw_key_len; i++) {
        uint32_t value = htonl(raw_key[i]); // Convert to big-endian
        memcpy(bytes + (i * sizeof(uint32_t)), &value, sizeof(uint32_t));
    }
    
    // Use BLAKE2b with a domain separation constant
    const char *domain = "LRS-AEAD-KEY";
    crypto_generichash_state state;
    crypto_generichash_init(&state, (const uint8_t*)domain, strlen(domain), 32);
    crypto_generichash_update(&state, bytes, bytes_len);
    crypto_generichash_final(&state, out_key, 32);
    
    // Clean up
    sodium_memzero(bytes, bytes_len);
    free(bytes);
    
    return 0;
}

// Encrypt data using XChaCha20-Poly1305 with support for password or raw key modes
int encrypt_blob_ex(const uint8_t *pt, size_t pt_len,
                  const void *key_material, int key_mode, const uint8_t *aad, size_t aad_len,
                  header_t *hdr, uint8_t *tlv_buffer, size_t tlv_buffer_size, uint8_t *ct, size_t *ct_len) {
    // Set up header with self-describing fields
    memcpy(hdr->magic, MAGIC, 3);
    hdr->version = VERSION;
    hdr->cipher_suite_id = CIPHER_XCHACHA20POLY1305;
    hdr->kdf_id = KDF_ARGON2ID;
    
    // Use configurable KDF parameters - stored in header for future compatibility
    // These can be adjusted based on the target system's capabilities
    // Convert to network byte order for cross-platform compatibility
    uint32_t mem_limit_kib = 512 * 1024; // 512MB in KiB
    hdr->kdf_ops = htonl(3);
    hdr->kdf_mem_limit_kib = htonl(mem_limit_kib);
    hdr->kdf_parallelism = htonl(1);

    // Set explicit lengths for salt and nonce
    hdr->salt_len = 16;
    hdr->nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    // Generate cryptographically secure random salt and nonce
    // XChaCha20 uses a 24-byte nonce which is large enough that random generation
    // is safe from collision even with the same key
    randombytes_buf(hdr->salt, hdr->salt_len);
    randombytes_buf(hdr->nonce, hdr->nonce_len); // Ensures unique nonce per encryption

    // Handle AAD (paths/doubts) consistently
    // Always hash the AAD to prevent length-based leaks
    if (aad != NULL && aad_len > 0) {
        // Hash the AAD using BLAKE2b
        hdr->aad_hash_id = HASH_BLAKE2B;
        hdr->aad_hash_len = 32; // BLAKE2b-256 output size
        crypto_generichash(hdr->aad_hash, hdr->aad_hash_len,
                          aad, aad_len, NULL, 0);
    } else {
        // No AAD provided
        hdr->aad_hash_id = 0;
        hdr->aad_hash_len = 0;
        sodium_memzero(hdr->aad_hash, sizeof(hdr->aad_hash));
    }

    // Add TLV data
    size_t tlv_pos = 0;
    
    // Add key mode TLV
    uint8_t key_mode_value = (uint8_t)key_mode;
    tlv_pos += add_tlv(tlv_buffer + tlv_pos, tlv_buffer_size - tlv_pos, 
                      TLV_KEY_MODE, &key_mode_value, 1);
    
    // Add timestamp TLV if space allows
    if (tlv_buffer_size - tlv_pos >= 10) { // 2 bytes for TLV header + 8 bytes for timestamp
        uint64_t timestamp = (uint64_t)time(NULL);
        uint64_t timestamp_be = htobe64(timestamp); // Convert to big-endian
        tlv_pos += add_tlv(tlv_buffer + tlv_pos, tlv_buffer_size - tlv_pos,
                          TLV_TIMESTAMP, (uint8_t*)&timestamp_be, 8);
    }
    
    // Set TLV length in header
    hdr->tlv_len = htons((uint16_t)tlv_pos);

    // Derive key based on mode
    uint8_t key[32];
    int kdf_result;
    
    if (key_mode == KEY_MODE_PASSWORD) {
        // Password mode - use Argon2id
        kdf_result = derive_key_argon2id((const char*)key_material, hdr->salt, 
                                        ntohl(hdr->kdf_mem_limit_kib), 
                                        ntohl(hdr->kdf_ops), 
                                        ntohl(hdr->kdf_parallelism), 
                                        key);
    } else if (key_mode == KEY_MODE_RAW_KEY) {
        // Raw key mode - use direct key derivation
        const uint32_t *raw_key = (const uint32_t*)key_material;
        size_t raw_key_len = 8; // Assuming 8 uint32_t values (32 bytes)
        kdf_result = derive_key_from_raw(raw_key, raw_key_len, key);
    } else {
        return -1; // Invalid key mode
    }
    
    if (kdf_result != 0) {
        // Key derivation failed
        return -1;
    }

    // Encrypt using XChaCha20-Poly1305
    unsigned long long clen = 0;
    int encrypt_result = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct, &clen, pt, pt_len, aad, aad_len, NULL, hdr->nonce, key);
    
    // Always zero out the key immediately after use
    sodium_memzero(key, sizeof key);
    
    // Check encryption result
    if (encrypt_result != 0) {
        return -2; // Encryption failed
    }

    *ct_len = (size_t)clen;
    return 0;
}

// Backward compatibility wrapper for encrypt_blob
int encrypt_blob(const uint8_t *pt, size_t pt_len,
                const char *pwd, const uint8_t *aad, size_t aad_len,
                header_t *hdr, uint8_t *ct, size_t *ct_len) {
    // Allocate a small buffer for TLV data
    uint8_t tlv_buffer[64] = {0};
    
    return encrypt_blob_ex(pt, pt_len, pwd, KEY_MODE_PASSWORD, aad, aad_len,
                         hdr, tlv_buffer, sizeof(tlv_buffer), ct, ct_len);
}

// Decrypt data using XChaCha20-Poly1305 with support for password or raw key modes
int decrypt_blob_ex(const uint8_t *ct, size_t ct_len,
                  const void *key_material, int key_mode, const uint8_t *aad, size_t aad_len,
                  const header_t *hdr, const uint8_t *tlv_data, size_t tlv_len,
                  uint8_t *pt, size_t *pt_len) {
    // Verify header magic and version
    // Refuse to process unknown versions for forward compatibility
    if (memcmp(hdr->magic, MAGIC, 3) != 0) {
        return -1; // Invalid magic bytes
    }
    
    // Version 2 is our target, but we can also handle version 1 for backward compatibility
    if (hdr->version != VERSION && hdr->version != 1) {
        return -2; // Unsupported version
    }

    // Verify cipher suite and KDF are supported
    if (hdr->cipher_suite_id != CIPHER_XCHACHA20POLY1305) {
        return -3; // Unsupported cipher suite
    }

    if (hdr->kdf_id != KDF_ARGON2ID) {
        return -4; // Unsupported KDF
    }

    // Verify salt and nonce lengths
    if (hdr->salt_len != 16 || hdr->nonce_len != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        return -5; // Invalid salt or nonce length
    }

    // Check for key mode in TLV data if available
    int detected_key_mode = key_mode; // Default to provided mode
    
    if (tlv_data && tlv_len > 0) {
        uint8_t tlv_key_mode_len = 0;
        const uint8_t *tlv_key_mode = find_tlv(tlv_data, tlv_len, TLV_KEY_MODE, &tlv_key_mode_len);
        
        if (tlv_key_mode && tlv_key_mode_len == 1) {
            detected_key_mode = *tlv_key_mode;
            
            // If key modes don't match, use the one from the TLV
            if (detected_key_mode != key_mode) {
                // We'll use the detected key mode instead of the provided one
                // This allows for automatic detection of the correct mode
            }
        }
    }

    // Derive key based on detected mode
    uint8_t key[32];
    int kdf_result;
    
    if (detected_key_mode == KEY_MODE_PASSWORD) {
        // Password mode - use Argon2id
        kdf_result = derive_key_argon2id((const char*)key_material, hdr->salt, 
                                        ntohl(hdr->kdf_mem_limit_kib), 
                                        ntohl(hdr->kdf_ops), 
                                        ntohl(hdr->kdf_parallelism), 
                                        key);
    } else if (detected_key_mode == KEY_MODE_RAW_KEY) {
        // Raw key mode - use direct key derivation
        const uint32_t *raw_key = (const uint32_t*)key_material;
        size_t raw_key_len = 8; // Assuming 8 uint32_t values (32 bytes)
        kdf_result = derive_key_from_raw(raw_key, raw_key_len, key);
    } else {
        return -6; // Invalid key mode
    }
    
    if (kdf_result != 0) {
        return -7; // Key derivation failed
    }

    // Decrypt using XChaCha20-Poly1305
    unsigned long long plen = 0;
    int decrypt_result = crypto_aead_xchacha20poly1305_ietf_decrypt(
        pt, &plen, NULL, ct, ct_len, aad, aad_len, hdr->nonce, key);
    
    // Always zero out the key immediately after use
    sodium_memzero(key, sizeof key);
    
    // Check decryption result - return nothing on failure
    if (decrypt_result != 0) {
        // Authentication or decryption failed - no partial output
        return -8; // auth fail => no output
    }

    *pt_len = (size_t)plen;
    return 0;
}

// Backward compatibility wrapper for decrypt_blob
int decrypt_blob(const uint8_t *ct, size_t ct_len,
                const char *pwd, const uint8_t *aad, size_t aad_len,
                const header_t *hdr, uint8_t *pt, size_t *pt_len) {
    // Extract TLV data if available (for version 2+)
    const uint8_t *tlv_data = NULL;
    size_t tlv_len = 0;
    
    if (hdr->version >= 2) {
        tlv_len = ntohs(hdr->tlv_len);
        // TLV data would be located after the header in the actual encrypted data
        // But we don't have access to it in this compatibility wrapper
    }
    
    return decrypt_blob_ex(ct, ct_len, pwd, KEY_MODE_PASSWORD, aad, aad_len,
                         hdr, tlv_data, tlv_len, pt, pt_len);
}

// Convert binary data to hexadecimal string
char* bin_to_hex(const uint8_t *data, size_t len) {
    char *hex = (char*)malloc(len * 2 + 1);
    if (!hex) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    
    return hex;
}

// Convert hexadecimal string to binary data
int hex_to_bin(const char *hex, uint8_t *bin, size_t *bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1; // Invalid hex string
    
    size_t len = hex_len / 2;
    if (len > *bin_len) return -1; // Buffer too small
    
    for (size_t i = 0; i < len; i++) {
        unsigned int val;
        if (sscanf(hex + (i * 2), "%02x", &val) != 1) {
            return -1; // Invalid hex character
        }
        bin[i] = (uint8_t)val;
    }
    
    *bin_len = len;
    return 0;
}

// Encrypt a string and return the result as a hex string
char* encrypt_string(const char *plaintext, const char *password, const char *paths) {
    if (!plaintext || !password) return NULL;
    
    // Initialize header
    header_t header;
    
    // Calculate sizes
    size_t pt_len = strlen(plaintext);
    size_t ct_len = pt_len + crypto_aead_xchacha20poly1305_ietf_ABYTES; // Ciphertext + auth tag
    
    // Allocate space for TLV data (up to 64 bytes)
    uint8_t tlv_buffer[64] = {0};
    size_t tlv_len = 0;
    
    // Calculate total length including header, TLV data, and ciphertext
    size_t total_len = sizeof(header) + 64 + ct_len; // Allocate max TLV space
    
    // Allocate memory for the encrypted data
    uint8_t *encrypted = (uint8_t*)malloc(total_len);
    if (!encrypted) return NULL;
    
    // Encrypt the plaintext
    // Handle paths/AAD consistently - NULL and empty string are treated the same
    const uint8_t *aad = NULL;
    size_t aad_len = 0;
    if (paths != NULL && paths[0] != '\0') {
        aad = (const uint8_t*)paths;
        aad_len = strlen(paths);
    }
    
    int encrypt_result = encrypt_blob_ex((const uint8_t*)plaintext, pt_len,
                    password, KEY_MODE_PASSWORD, aad, aad_len,
                    &header, tlv_buffer, sizeof(tlv_buffer), 
                    encrypted + sizeof(header) + ntohs(header.tlv_len), &ct_len);
    
    if (encrypt_result != 0) {
        // Clean up on encryption failure
        sodium_memzero(encrypted, total_len);
        free(encrypted);
        return NULL;
    }
    
    // Get actual TLV length from header
    tlv_len = ntohs(header.tlv_len);
    
    // Copy the header to the beginning of the encrypted data
    memcpy(encrypted, &header, sizeof(header));
    
    // Copy the TLV data after the header
    if (tlv_len > 0) {
        memcpy(encrypted + sizeof(header), tlv_buffer, tlv_len);
    }
    
    // Calculate actual total length
    total_len = sizeof(header) + tlv_len + ct_len;
    
    // Convert the encrypted data to a hex string
    char *hex = bin_to_hex(encrypted, total_len);
    free(encrypted);
    
    return hex;
}

// Decrypt a hex string and return the plaintext
char* decrypt_string(const char *hex_string, const char *password, const char *paths) {
    if (!hex_string || !password) return NULL;
    
    // Calculate the maximum possible size of the binary data
    size_t hex_len = strlen(hex_string);
    size_t bin_max_len = hex_len / 2;
    
    // Allocate memory for the binary data
    uint8_t *encrypted = (uint8_t*)malloc(bin_max_len);
    if (!encrypted) return NULL;
    
    // Convert the hex string to binary data
    size_t bin_len = bin_max_len;
    if (hex_to_bin(hex_string, encrypted, &bin_len) != 0 || bin_len < sizeof(header_t)) {
        free(encrypted);
        return NULL;
    }
    
    // Extract the header
    header_t header;
    memcpy(&header, encrypted, sizeof(header));
    
    // Get TLV length from header if version 2+
    size_t tlv_len = 0;
    if (header.version >= 2) {
        tlv_len = ntohs(header.tlv_len);
    }
    
    // Calculate the ciphertext offset and length
    size_t header_offset = sizeof(header) + tlv_len;
    size_t ct_len = bin_len - header_offset;
    
    // Allocate memory for the plaintext (will be smaller than ciphertext)
    uint8_t *plaintext = (uint8_t*)malloc(ct_len);
    if (!plaintext) {
        free(encrypted);
        return NULL;
    }
    
    // Decrypt the ciphertext
    // Handle paths/AAD consistently - NULL and empty string are treated the same
    const uint8_t *aad = NULL;
    size_t aad_len = 0;
    if (paths != NULL && paths[0] != '\0') {
        aad = (const uint8_t*)paths;
        aad_len = strlen(paths);
    }
    
    // Extract TLV data if present
    const uint8_t *tlv_data = NULL;
    if (tlv_len > 0) {
        tlv_data = encrypted + sizeof(header);
    }
    
    size_t pt_len;
    int result = decrypt_blob_ex(encrypted + header_offset, ct_len,
                             password, KEY_MODE_PASSWORD,
                             aad, aad_len,
                             &header, tlv_data, tlv_len, plaintext, &pt_len);
    
    free(encrypted);
    
    if (result != 0) {
        // On decryption failure, return nothing - no partial plaintext
        // Use the buffer size we allocated earlier
        sodium_memzero(plaintext, ct_len);
        free(plaintext);
        return NULL;
    }
    
    // Ensure the plaintext is null-terminated
    char *output = (char*)realloc(plaintext, pt_len + 1);
    if (!output) {
        free(plaintext);
        return NULL;
    }
    output[pt_len] = '\0';
    
    return output;
}

// Encrypt a file
int encrypt_file(const char *input_file, const char *output_file, const char *password, const char *paths) {
    if (!input_file || !output_file || !password) return -1;
    
    // Open input file
    FILE *in = fopen(input_file, "rb");
    if (!in) return -1;
    
    // Get file size
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    if (file_size < 0) {
        fclose(in);
        return -1;
    }
    
    // Read file content
    uint8_t *plaintext = (uint8_t*)malloc(file_size);
    if (!plaintext) {
        fclose(in);
        return -1;
    }
    
    size_t bytes_read = fread(plaintext, 1, file_size, in);
    fclose(in);
    
    if (bytes_read != (size_t)file_size) {
        free(plaintext);
        return -1;
    }
    
    // Initialize header
    header_t header;
    
    // Allocate space for TLV data (up to 64 bytes)
    uint8_t tlv_buffer[64] = {0};
    
    // Calculate ciphertext size
    size_t ct_len = file_size + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    uint8_t *ciphertext = (uint8_t*)malloc(ct_len);
    if (!ciphertext) {
        free(plaintext);
        return -1;
    }
    
    // Encrypt the file content
    // Handle paths/AAD consistently - NULL and empty string are treated the same
    const uint8_t *aad = NULL;
    size_t aad_len = 0;
    if (paths != NULL && paths[0] != '\0') {
        aad = (const uint8_t*)paths;
        aad_len = strlen(paths);
    }
    
    int encrypt_result = encrypt_blob_ex(plaintext, file_size,
                    password, KEY_MODE_PASSWORD,
                    aad, aad_len,
                    &header, tlv_buffer, sizeof(tlv_buffer), ciphertext, &ct_len);
                    
    if (encrypt_result != 0) {
        // Clean up on encryption failure
        sodium_memzero(plaintext, file_size);
        free(plaintext);
        free(ciphertext);
        return -1;
    }
    
    free(plaintext);
    
    // Get actual TLV length from header
    size_t tlv_len = ntohs(header.tlv_len);
    
    // Open output file
    FILE *out = fopen(output_file, "wb");
    if (!out) {
        free(ciphertext);
        return -1;
    }
    
    // Write header
    if (fwrite(&header, sizeof(header), 1, out) != 1) {
        fclose(out);
        free(ciphertext);
        return -1;
    }
    
    // Write TLV data if present
    if (tlv_len > 0) {
        if (fwrite(tlv_buffer, 1, tlv_len, out) != tlv_len) {
            fclose(out);
            free(ciphertext);
            return -1;
        }
    }
    
    // Write ciphertext
    if (fwrite(ciphertext, 1, ct_len, out) != ct_len) {
        fclose(out);
        free(ciphertext);
        return -1;
    }
    
    fclose(out);
    free(ciphertext);
    
    return 0; // Success
}

// Decrypt a file
int decrypt_file(const char *input_file, const char *output_file, const char *password, const char *paths) {
    if (!input_file || !output_file || !password) return -1;
    
    // Open input file
    FILE *in = fopen(input_file, "rb");
    if (!in) return -1;
    
    // Get file size
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    if (file_size < (long)sizeof(header_t)) {
        fclose(in);
        return -1; // File too small to contain header
    }
    
    // Read header
    header_t header;
    if (fread(&header, sizeof(header), 1, in) != 1) {
        fclose(in);
        return -1;
    }
    
    // Verify header magic and version
    if (memcmp(header.magic, MAGIC, 3) != 0 || 
        (header.version != VERSION && header.version != 1)) {
        fclose(in);
        return -1; // Invalid header
    }
    
    // Get TLV length from header if version 2+
    size_t tlv_len = 0;
    uint8_t *tlv_data = NULL;
    if (header.version >= 2) {
        tlv_len = ntohs(header.tlv_len);
        
        // Read TLV data if present
        if (tlv_len > 0) {
            tlv_data = (uint8_t*)malloc(tlv_len);
            if (!tlv_data) {
                fclose(in);
                return -1;
            }
            
            if (fread(tlv_data, 1, tlv_len, in) != tlv_len) {
                free(tlv_data);
                fclose(in);
                return -1;
            }
        }
    }
    
    // Calculate ciphertext size
    size_t ct_len = file_size - sizeof(header) - tlv_len;
    uint8_t *ciphertext = (uint8_t*)malloc(ct_len);
    if (!ciphertext) {
        if (tlv_data) free(tlv_data);
        fclose(in);
        return -1;
    }
    
    // Read ciphertext
    if (fread(ciphertext, 1, ct_len, in) != ct_len) {
        fclose(in);
        free(ciphertext);
        if (tlv_data) free(tlv_data);
        return -1;
    }
    
    fclose(in);
    
    // Allocate memory for plaintext (will be smaller than ciphertext)
    uint8_t *plaintext = (uint8_t*)malloc(ct_len);
    if (!plaintext) {
        free(ciphertext);
        if (tlv_data) free(tlv_data);
        return -1;
    }
    
    // Decrypt the ciphertext
    // Handle paths/AAD consistently - NULL and empty string are treated the same
    const uint8_t *aad = NULL;
    size_t aad_len = 0;
    if (paths != NULL && paths[0] != '\0') {
        aad = (const uint8_t*)paths;
        aad_len = strlen(paths);
    }
    
    size_t pt_len;
    int result = decrypt_blob_ex(ciphertext, ct_len,
                             password, KEY_MODE_PASSWORD,
                             aad, aad_len,
                             &header, tlv_data, tlv_len, plaintext, &pt_len);
    
    free(ciphertext);
    if (tlv_data) free(tlv_data);
    
    if (result != 0) {
        // On decryption failure, zero out the plaintext buffer
        sodium_memzero(plaintext, ct_len);
        free(plaintext);
        return result; // Decryption failed
    }
    
    // Open output file
    FILE *out = fopen(output_file, "wb");
    if (!out) {
        free(plaintext);
        return -1;
    }
    
    // Write plaintext
    if (fwrite(plaintext, 1, pt_len, out) != pt_len) {
        fclose(out);
        free(plaintext);
        return -1;
    }
    
    fclose(out);
    free(plaintext);
    
    return 0; // Success
}