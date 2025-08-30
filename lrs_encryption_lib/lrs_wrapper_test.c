#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>

// Forward declarations for wrapper functions
void encrypt_message(const char* message, uint32_t key, uint32_t* output, int* output_len);
void decrypt_message(const uint32_t* encrypted, int encrypted_len, uint32_t key, char* output);
int encrypt_file_wrapper(const char* input_file, const char* output_file, uint32_t key);
int decrypt_file_wrapper(const char* input_file, const char* output_file, uint32_t key);

// Forward declarations for raw key mode functions
int encrypt_file_raw_key(const char* input_file, const char* output_file, const void* key_material, int key_mode);
int decrypt_file_raw_key(const char* input_file, const char* output_file, const void* key_material, int key_mode);

// Key mode constants
#define KEY_MODE_PASSWORD 0
#define KEY_MODE_RAW_KEY 1

// Simple key derivation for testing
uint32_t derive_key(const char* password) {
    uint32_t key = 0x12345678; // Start with a seed
    
    for (size_t i = 0; i < strlen(password); i++) {
        key = ((key << 5) | (key >> 27)) ^ password[i];
    }
    
    return key;
}

// Convert uint32 array to hex string for display
void uint32_to_hex(const uint32_t* data, int len, char* output) {
    output[0] = '\0';
    for (int i = 0; i < len; i++) {
        char hex[9];
        sprintf(hex, "%08x", data[i]); // Use lowercase hex to match libsodium
        strcat(output, hex);
    }
}

// Helper function to compare two files
void compare_files(const char* file1, const char* file2, const char* test_name) {
    FILE* f1 = fopen(file1, "rb");
    FILE* f2 = fopen(file2, "rb");
    
    if (!f1 || !f2) {
        printf("  ✗ %s: Failed to open files for comparison\n", test_name);
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        return;
    }
    
    int same = 1;
    int c1, c2;
    
    while ((c1 = fgetc(f1)) != EOF && (c2 = fgetc(f2)) != EOF) {
        if (c1 != c2) {
            same = 0;
            break;
        }
    }
    
    if (same && fgetc(f1) == EOF && fgetc(f2) == EOF) {
        printf("  ✓ %s: File content matches perfectly\n", test_name);
    } else {
        printf("  ✗ %s: File content mismatch\n", test_name);
    }
    
    fclose(f1);
    fclose(f2);
}

// Test raw key mode encryption/decryption
void test_raw_key_mode() {
    printf("\n=== Testing Raw Key Mode ===\n\n");
    
    // Create test file
    FILE* test_file = fopen("raw_key_test_file.txt", "w");
    if (!test_file) {
        printf("  ✗ Failed to create test file\n");
        return;
    }
    
    fprintf(test_file, "This is a test file for the raw key mode.\n");
    fprintf(test_file, "Testing direct key usage without password KDF.\n");
    fclose(test_file);
    
    // Create a raw key (32-bit integers)
    uint32_t raw_key[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};
    
    printf("Raw key: %08x %08x %08x %08x\n\n", 
           raw_key[0], raw_key[1], raw_key[2], raw_key[3]);
    
    // Test raw key encryption
    if (encrypt_file_raw_key("raw_key_test_file.txt", "raw_key_test_file.enc", 
                            raw_key, KEY_MODE_RAW_KEY) == 0) {
        printf("  ✓ File encrypted with raw key successfully\n");
        
        // Test raw key decryption
        if (decrypt_file_raw_key("raw_key_test_file.enc", "raw_key_test_file_dec.txt", 
                                raw_key, KEY_MODE_RAW_KEY) == 0) {
            printf("  ✓ File decrypted with raw key successfully\n");
            
            // Compare files
            compare_files("raw_key_test_file.txt", "raw_key_test_file_dec.txt", "Raw key mode");
        } else {
            printf("  ✗ Raw key file decryption failed\n");
        }
    } else {
        printf("  ✗ Raw key file encryption failed\n");
    }
    
    // Clean up test files
    remove("raw_key_test_file.txt");
    remove("raw_key_test_file.enc");
    remove("raw_key_test_file_dec.txt");
}

int main() {
    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }
    
    printf("=== Testing LRS Wrapper Functions ===\n\n");
    
    const char* test_messages[] = {
        "Hello, World!",
        "This is a test message.",
        "Testing the LRS wrapper functions."
    };
    
    uint32_t key = derive_key("test_password");
    printf("Test key: 0x%08x\n\n", key); // Use lowercase hex to match libsodium
    
    // Test string encryption/decryption
    for (int i = 0; i < 3; i++) {
        printf("Test %d:\n", i + 1);
        printf("  Original: %s\n", test_messages[i]);
        
        uint32_t encrypted[256];
        int encrypted_len;
        encrypt_message(test_messages[i], key, encrypted, &encrypted_len);
        
        char hex_output[1024];
        uint32_to_hex(encrypted, encrypted_len, hex_output);
        printf("  Encrypted: %s\n", hex_output);
        
        char decrypted[256];
        decrypt_message(encrypted, encrypted_len, key, decrypted);
        printf("  Decrypted: %s\n", decrypted);
        
        if (strcmp(test_messages[i], decrypted) == 0) {
            printf("  ✓ SUCCESS\n");
        } else {
            printf("  ✗ FAILED\n");
        }
        printf("\n");
    }
    
    // Test file encryption/decryption
    printf("File encryption test (legacy wrapper):\n");
    
    // Create test file
    FILE* test_file = fopen("wrapper_test_file.txt", "w");
    if (!test_file) {
        printf("  ✗ Failed to create test file\n");
        return 1;
    }
    
    fprintf(test_file, "This is a test file for the LRS wrapper.\n");
    fprintf(test_file, "It contains multiple lines and special chars: !@#$%%^&*()\n");
    fclose(test_file);
    
    // Test file encryption
    if (encrypt_file_wrapper("wrapper_test_file.txt", "wrapper_test_file.enc", key) == 0) {
        printf("  ✓ File encrypted successfully\n");
        
        // Test file decryption
        if (decrypt_file_wrapper("wrapper_test_file.enc", "wrapper_test_file_dec.txt", key) == 0) {
            printf("  ✓ File decrypted successfully\n");
            
            // Compare files
            compare_files("wrapper_test_file.txt", "wrapper_test_file_dec.txt", "Legacy wrapper");
        } else {
            printf("  ✗ File decryption failed\n");
        }
    } else {
        printf("  ✗ File encryption failed\n");
    }
    
    // Clean up test files
    remove("wrapper_test_file.txt");
    remove("wrapper_test_file.enc");
    remove("wrapper_test_file_dec.txt");
    
    // Test raw key mode
    test_raw_key_mode();
    
    printf("\nAll wrapper tests completed!\n");
    return 0;
}