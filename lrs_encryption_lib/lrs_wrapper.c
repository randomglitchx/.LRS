#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "lrs_encryption_lib.h"

// Forward declarations for the new implementation
extern char* encrypt_string(const char *plaintext, const char *password, const char *paths);
extern char* decrypt_string(const char *hex_string, const char *password, const char *paths);
extern int encrypt_file(const char *input_file, const char *output_file, const char *password, const char *paths);
extern int decrypt_file(const char *input_file, const char *output_file, const char *password, const char *paths);

// New raw key mode functions
extern int encrypt_blob_ex(const uint8_t *plaintext, size_t pt_len, 
                      const void *key_material, int key_mode,
                      const uint8_t *aad, size_t aad_len,
                      header_t *header, uint8_t *tlv_buffer, size_t tlv_buffer_size,
                      uint8_t *ciphertext, size_t *ct_len);
extern int decrypt_blob_ex(const uint8_t *ciphertext, size_t ct_len,
                      const void *key_material, int key_mode,
                      const uint8_t *aad, size_t aad_len,
                      const header_t *header, const uint8_t *tlv_data, size_t tlv_len,
                      uint8_t *plaintext, size_t *pt_len);

// Key mode constants
#define KEY_MODE_PASSWORD 0
#define KEY_MODE_RAW_KEY 1

// Store the last encrypted string for use in decrypt_message
char last_encrypted[4096];

// Helper function to convert binary data to hex string (static to avoid conflicts)
static char* bin_to_hex(const uint8_t* bin, size_t bin_len) {
    if (!bin || bin_len == 0) return NULL;
    
    // Allocate memory for hex string (2 chars per byte + null terminator)
    char* hex = (char*)malloc(bin_len * 2 + 1);
    if (!hex) return NULL;
    
    // Convert each byte to hex
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    
    hex[bin_len * 2] = '\0';
    return hex;
}

// Helper function to convert hex string to binary data (static to avoid conflicts)
static uint8_t* hex_to_bin(const char* hex, size_t* bin_len) {
    if (!hex || !bin_len) return NULL;
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return NULL; // Hex string must have even length
    
    *bin_len = hex_len / 2;
    uint8_t* bin = (uint8_t*)malloc(*bin_len);
    if (!bin) return NULL;
    
    // Convert each hex pair to a byte
    for (size_t i = 0; i < *bin_len; i++) {
        char hex_byte[3] = {hex[i*2], hex[i*2+1], '\0'};
        bin[i] = (uint8_t)strtoul(hex_byte, NULL, 16);
    }
    
    return bin;
}

// Wrapper function to maintain compatibility with the old API
void encrypt_message(const char* message, uint32_t key, uint32_t* output, int* output_len) {
    // Convert the uint32_t key to a string password
    char password[16];
    snprintf(password, sizeof(password), "%08x", key); // Use lowercase hex
    
    // Use the encrypt_string function with password mode
    char* encrypted_hex = encrypt_string(message, password, NULL);
    if (!encrypted_hex) {
        *output_len = 0;
        return;
    }
    
    // Store the encrypted string for later use
    strncpy(last_encrypted, encrypted_hex, sizeof(last_encrypted) - 1);
    last_encrypted[sizeof(last_encrypted) - 1] = '\0';
    
    // Convert the hex string to uint32_t array
    size_t hex_len = strlen(encrypted_hex);
    *output_len = hex_len / 8; // Each uint32_t is 8 hex chars
    
    for (int i = 0; i < *output_len; i++) {
        char hex_chunk[9];
        strncpy(hex_chunk, encrypted_hex + (i * 8), 8);
        hex_chunk[8] = '\0';
        output[i] = (uint32_t)strtoul(hex_chunk, NULL, 16);
    }
    
    free(encrypted_hex);
}

// Wrapper function to maintain compatibility with the old API
void decrypt_message(const uint32_t* encrypted, int encrypted_len, uint32_t key, char* output) {
    // Convert the uint32_t key to a string password
    char password[16];
    snprintf(password, sizeof(password), "%08x", key); // Use lowercase hex
    
    // Reconstruct the hex string from the uint32_t array
    char hex_string[4096] = {0};
    for (int i = 0; i < encrypted_len; i++) {
        char hex_chunk[9];
        sprintf(hex_chunk, "%08x", encrypted[i]);
        strcat(hex_string, hex_chunk);
    }
    
    // Use the decrypt_string function with password mode
    char* decrypted = decrypt_string(hex_string, password, NULL);
    if (!decrypted) {
        output[0] = '\0';
        return;
    }
    
    // Copy the result to the output buffer
    strcpy(output, decrypted);
    
    // Clean up
    free(decrypted);
}

// Raw key mode file encryption function
int encrypt_file_raw_key(const char *input_file, const char *output_file, const void *key_material, int key_mode) {
    if (!input_file || !output_file || !key_material) return -1;
    
    // Open input file
    FILE *in_fp = fopen(input_file, "rb");
    if (!in_fp) return -1;
    
    // Get file size
    fseek(in_fp, 0, SEEK_END);
    long file_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    
    if (file_size < 0) {
        fclose(in_fp);
        return -1;
    }
    
    // Allocate memory for plaintext
    uint8_t *plaintext = (uint8_t*)malloc(file_size);
    if (!plaintext) {
        fclose(in_fp);
        return -1;
    }
    
    // Read plaintext
    size_t bytes_read = fread(plaintext, 1, file_size, in_fp);
    fclose(in_fp);
    
    if (bytes_read != (size_t)file_size) {
        free(plaintext);
        return -1;
    }
    
    // Initialize header
    header_t header;
    
    // Allocate space for TLV data (up to 64 bytes)
    uint8_t tlv_buffer[64] = {0};
    
    // Calculate ciphertext size
    size_t pt_len = (size_t)file_size;
    size_t ct_len = pt_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    
    // Allocate memory for ciphertext
    uint8_t *ciphertext = (uint8_t*)malloc(ct_len);
    if (!ciphertext) {
        free(plaintext);
        return -1;
    }
    
    // Encrypt the plaintext
    int encrypt_result = encrypt_blob_ex(plaintext, pt_len,
                    key_material, key_mode, NULL, 0,
                    &header, tlv_buffer, sizeof(tlv_buffer), ciphertext, &ct_len);
    
    // Clean up plaintext
    sodium_memzero(plaintext, pt_len);
    free(plaintext);
    
    if (encrypt_result != 0) {
        // Clean up on encryption failure
        sodium_memzero(ciphertext, ct_len);
        free(ciphertext);
        return -1;
    }
    
    // Get actual TLV length from header
    size_t tlv_len = ntohs(header.tlv_len);
    
    // Open output file
    FILE *out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        sodium_memzero(ciphertext, ct_len);
        free(ciphertext);
        return -1;
    }
    
    // Write header
    size_t header_written = fwrite(&header, 1, sizeof(header), out_fp);
    if (header_written != sizeof(header)) {
        fclose(out_fp);
        sodium_memzero(ciphertext, ct_len);
        free(ciphertext);
        return -1;
    }
    
    // Write TLV data if present
    if (tlv_len > 0) {
        size_t tlv_written = fwrite(tlv_buffer, 1, tlv_len, out_fp);
        if (tlv_written != tlv_len) {
            fclose(out_fp);
            sodium_memzero(ciphertext, ct_len);
            free(ciphertext);
            return -1;
        }
    }
    
    // Write ciphertext
    size_t ct_written = fwrite(ciphertext, 1, ct_len, out_fp);
    
    // Clean up ciphertext
    sodium_memzero(ciphertext, ct_len);
    free(ciphertext);
    fclose(out_fp);
    
    if (ct_written != ct_len) {
        return -1;
    }
    
    return 0;
}

// Raw key mode file decryption function
int decrypt_file_raw_key(const char *input_file, const char *output_file, const void *key_material, int key_mode) {
    if (!input_file || !output_file || !key_material) return -1;
    
    // Open input file
    FILE *in_fp = fopen(input_file, "rb");
    if (!in_fp) return -1;
    
    // Get file size
    fseek(in_fp, 0, SEEK_END);
    long file_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    
    if (file_size < 0 || file_size < (long)sizeof(header_t)) {
        fclose(in_fp);
        return -1;
    }
    
    // Read header
    header_t header;
    size_t header_read = fread(&header, 1, sizeof(header), in_fp);
    if (header_read != sizeof(header)) {
        fclose(in_fp);
        return -1;
    }
    
    // Verify header magic and version
    if (memcmp(header.magic, "LRS", 3) != 0 || 
        (header.version != 1 && header.version != 2)) {
        fclose(in_fp);
        return -1;
    }
    
    // Get TLV length from header if version 2+
    size_t tlv_len = 0;
    if (header.version >= 2) {
        tlv_len = ntohs(header.tlv_len);
    }
    
    // Read TLV data if present
    uint8_t *tlv_data = NULL;
    if (tlv_len > 0) {
        tlv_data = (uint8_t*)malloc(tlv_len);
        if (!tlv_data) {
            fclose(in_fp);
            return -1;
        }
        
        size_t tlv_read = fread(tlv_data, 1, tlv_len, in_fp);
        if (tlv_read != tlv_len) {
            free(tlv_data);
            fclose(in_fp);
            return -1;
        }
    }
    
    // Calculate ciphertext size
    size_t ct_len = file_size - sizeof(header) - tlv_len;
    
    // Allocate memory for ciphertext
    uint8_t *ciphertext = (uint8_t*)malloc(ct_len);
    if (!ciphertext) {
        if (tlv_data) free(tlv_data);
        fclose(in_fp);
        return -1;
    }
    
    // Read ciphertext
    size_t ct_read = fread(ciphertext, 1, ct_len, in_fp);
    fclose(in_fp);
    
    if (ct_read != ct_len) {
        free(ciphertext);
        if (tlv_data) free(tlv_data);
        return -1;
    }
    
    // Calculate plaintext size (will be smaller than ciphertext)
    size_t pt_len = ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    
    // Allocate memory for plaintext
    uint8_t *plaintext = (uint8_t*)malloc(pt_len);
    if (!plaintext) {
        free(ciphertext);
        if (tlv_data) free(tlv_data);
        return -1;
    }
    
    // Decrypt the ciphertext
    int decrypt_result = decrypt_blob_ex(ciphertext, ct_len,
                    key_material, key_mode, NULL, 0,
                    &header, tlv_data, tlv_len, plaintext, &pt_len);
    
    // Clean up ciphertext and TLV data
    free(ciphertext);
    if (tlv_data) free(tlv_data);
    
    if (decrypt_result != 0) {
        // Clean up on decryption failure
        sodium_memzero(plaintext, pt_len);
        free(plaintext);
        return -1;
    }
    
    // Open output file
    FILE *out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        sodium_memzero(plaintext, pt_len);
        free(plaintext);
        return -1;
    }
    
    // Write plaintext
    size_t pt_written = fwrite(plaintext, 1, pt_len, out_fp);
    
    // Clean up plaintext
    sodium_memzero(plaintext, pt_len);
    free(plaintext);
    fclose(out_fp);
    
    if (pt_written != pt_len) {
        return -1;
    }
    
    return 0;
}

// Wrapper function to maintain compatibility with the old API
int encrypt_file_wrapper(const char* input_file, const char* output_file, uint32_t key) {
    // Convert the uint32_t key to a string password
    char password[16];
    snprintf(password, sizeof(password), "%08x", key); // Use lowercase hex
    
    // Use the new implementation with password mode
    return encrypt_file(input_file, output_file, password, NULL);
}

// Wrapper function to maintain compatibility with the old API
int decrypt_file_wrapper(const char* input_file, const char* output_file, uint32_t key) {
    // Convert the uint32_t key to a string password
    char password[16];
    snprintf(password, sizeof(password), "%08x", key); // Use lowercase hex
    
    // Use the new implementation with password mode
    return decrypt_file(input_file, output_file, password, NULL);
}