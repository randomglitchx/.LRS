#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define MAGIC "LRS1"
#define VERSION 1

typedef struct {
    char magic[4];
    uint8_t version;
    uint8_t kdf_mem_log2;   // e.g., 28 => ~256MB
    uint8_t kdf_ops;        // e.g., 3
    uint8_t kdf_parallel;   // e.g., 1
    uint8_t reserved[3];
    uint8_t salt[16];
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]; // 24
    uint8_t paths_hash[16]; // Optional hash of paths/doubts
} header_t;

// Derive key using Argon2id
int derive_key_argon2id(const char *pwd, const uint8_t salt[16],
                       uint8_t mem_log2, uint8_t ops, uint8_t parallel,
                       uint8_t out_key[32]) {
    unsigned long long mem = 1ULL << mem_log2; // bytes
    return crypto_pwhash(out_key, 32, pwd, strlen(pwd), salt,
        ops,
        mem,
        crypto_pwhash_ALG_ARGON2ID13);
}

// Encrypt data using XChaCha20-Poly1305
int encrypt_blob(const uint8_t *pt, size_t pt_len,
                const char *pwd, const uint8_t *aad, size_t aad_len,
                header_t *hdr, uint8_t *ct, size_t *ct_len) {
    // Set up header
    memcpy(hdr->magic, MAGIC, 4);
    hdr->version = VERSION;
    hdr->kdf_mem_log2 = 28;  // ~256MB
    hdr->kdf_ops = 3;
    hdr->kdf_parallel = 1;
    memset(hdr->reserved, 0, sizeof hdr->reserved);

    // Generate random salt and nonce
    randombytes_buf(hdr->salt, sizeof hdr->salt);
    randombytes_buf(hdr->nonce, sizeof hdr->nonce);

    // If paths/doubts are provided, store a hash of them
    if (aad != NULL && aad_len > 0) {
        crypto_generichash(hdr->paths_hash, sizeof(hdr->paths_hash), aad, aad_len, NULL, 0);
    } else {
        memset(hdr->paths_hash, 0, sizeof(hdr->paths_hash));
    }

    // Derive key using Argon2id
    uint8_t key[32];
    if (derive_key_argon2id(pwd, hdr->salt, hdr->kdf_mem_log2, hdr->kdf_ops, hdr->kdf_parallel, key) != 0) {
        return -1;
    }

    // Encrypt using XChaCha20-Poly1305
    unsigned long long clen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &clen,
            pt, pt_len, aad, aad_len,
            NULL, hdr->nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        return -1;
    }

    *ct_len = (size_t)clen;
    sodium_memzero(key, sizeof key);
    return 0;
}

// Decrypt data using XChaCha20-Poly1305
int decrypt_blob(const uint8_t *ct, size_t ct_len,
                const char *pwd, const uint8_t *aad, size_t aad_len,
                const header_t *hdr, uint8_t *pt, size_t *pt_len) {
    // Verify header
    if (memcmp(hdr->magic, MAGIC, 4) || hdr->version != VERSION) {
        return -1;
    }

    // Derive key using Argon2id
    uint8_t key[32];
    if (derive_key_argon2id(pwd, hdr->salt, hdr->kdf_mem_log2, hdr->kdf_ops, hdr->kdf_parallel, key) != 0) {
        return -1;
    }

    // Decrypt using XChaCha20-Poly1305
    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &plen,
            NULL, ct, ct_len, aad, aad_len, hdr->nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        return -1; // auth fail => no output
    }

    *pt_len = (size_t)plen;
    sodium_memzero(key, sizeof key);
    return 0;
}

// Encrypt a file
int encrypt_file(const char *input_file, const char *output_file, const char *password, const char *paths) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        printf("Error: Cannot open input file '%s'\n", input_file);
        return -1;
    }

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        printf("Error: Cannot create output file '%s'\n", output_file);
        fclose(in);
        return -1;
    }

    // Get file size
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    fseek(in, 0, SEEK_SET);

    // Read entire file into memory
    uint8_t *file_data = malloc(file_size);
    if (!file_data) {
        printf("Error: Memory allocation failed\n");
        fclose(in);
        fclose(out);
        return -1;
    }

    if (fread(file_data, 1, file_size, in) != (size_t)file_size) {
        printf("Error: Failed to read input file\n");
        free(file_data);
        fclose(in);
        fclose(out);
        return -1;
    }

    // Prepare for encryption
    header_t header;
    size_t ciphertext_len;
    uint8_t *ciphertext = malloc(file_size + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    if (!ciphertext) {
        printf("Error: Memory allocation failed\n");
        free(file_data);
        fclose(in);
        fclose(out);
        return -1;
    }

    // Encrypt the file data
    if (encrypt_blob(file_data, file_size, password, 
                    (uint8_t*)paths, paths ? strlen(paths) : 0,
                    &header, ciphertext, &ciphertext_len) != 0) {
        printf("Error: Encryption failed\n");
        free(file_data);
        free(ciphertext);
        fclose(in);
        fclose(out);
        return -1;
    }

    // Write header and ciphertext to output file
    if (fwrite(&header, sizeof(header), 1, out) != 1 ||
        fwrite(ciphertext, 1, ciphertext_len, out) != ciphertext_len) {
        printf("Error: Failed to write output file\n");
        free(file_data);
        free(ciphertext);
        fclose(in);
        fclose(out);
        return -1;
    }

    free(file_data);
    free(ciphertext);
    fclose(in);
    fclose(out);
    return 0;
}

// Decrypt a file
int decrypt_file(const char *input_file, const char *output_file, const char *password, const char *paths) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        printf("Error: Cannot open input file '%s'\n", input_file);
        return -1;
    }

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        printf("Error: Cannot create output file '%s'\n", output_file);
        fclose(in);
        return -1;
    }

    // Read header
    header_t header;
    if (fread(&header, sizeof(header), 1, in) != 1) {
        printf("Error: Failed to read file header\n");
        fclose(in);
        fclose(out);
        return -1;
    }

    // Verify magic and version
    if (memcmp(header.magic, MAGIC, 4) != 0 || header.version != VERSION) {
        printf("Error: Invalid file format or version\n");
        fclose(in);
        fclose(out);
        return -1;
    }

    // Get ciphertext size
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    long ciphertext_size = file_size - sizeof(header);
    fseek(in, sizeof(header), SEEK_SET);

    // Read ciphertext
    uint8_t *ciphertext = malloc(ciphertext_size);
    if (!ciphertext) {
        printf("Error: Memory allocation failed\n");
        fclose(in);
        fclose(out);
        return -1;
    }

    if (fread(ciphertext, 1, ciphertext_size, in) != (size_t)ciphertext_size) {
        printf("Error: Failed to read ciphertext\n");
        free(ciphertext);
        fclose(in);
        fclose(out);
        return -1;
    }

    // Allocate memory for plaintext
    size_t max_plaintext_size = ciphertext_size - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    uint8_t *plaintext = malloc(max_plaintext_size);
    if (!plaintext) {
        printf("Error: Memory allocation failed\n");
        free(ciphertext);
        fclose(in);
        fclose(out);
        return -1;
    }

    // Decrypt the data
    size_t plaintext_len;
    if (decrypt_blob(ciphertext, ciphertext_size, password,
                    (uint8_t*)paths, paths ? strlen(paths) : 0,
                    &header, plaintext, &plaintext_len) != 0) {
        printf("Error: Decryption failed (wrong password or tampered data)\n");
        free(ciphertext);
        free(plaintext);
        fclose(in);
        fclose(out);
        return -1;
    }

    // Write plaintext to output file
    if (fwrite(plaintext, 1, plaintext_len, out) != plaintext_len) {
        printf("Error: Failed to write output file\n");
        free(ciphertext);
        free(plaintext);
        fclose(in);
        fclose(out);
        return -1;
    }

    free(ciphertext);
    free(plaintext);
    fclose(in);
    fclose(out);
    return 0;
}

// Encrypt a string
char* encrypt_string(const char *plaintext, const char *password, const char *paths) {
    size_t plaintext_len = strlen(plaintext);
    header_t header;
    size_t ciphertext_len;
    
    // Allocate memory for ciphertext
    uint8_t *ciphertext = malloc(plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    if (!ciphertext) {
        return NULL;
    }
    
    // Encrypt the plaintext
    if (encrypt_blob((uint8_t*)plaintext, plaintext_len, password,
                    (uint8_t*)paths, paths ? strlen(paths) : 0,
                    &header, ciphertext, &ciphertext_len) != 0) {
        free(ciphertext);
        return NULL;
    }
    
    // Allocate memory for the result (header + ciphertext)
    size_t result_size = sizeof(header) + ciphertext_len;
    uint8_t *result_binary = malloc(result_size);
    if (!result_binary) {
        free(ciphertext);
        return NULL;
    }
    
    // Copy header and ciphertext to result
    memcpy(result_binary, &header, sizeof(header));
    memcpy(result_binary + sizeof(header), ciphertext, ciphertext_len);
    
    // Convert binary result to hex string
    char *hex_result = malloc(result_size * 2 + 1);
    if (!hex_result) {
        free(ciphertext);
        free(result_binary);
        return NULL;
    }
    
    for (size_t i = 0; i < result_size; i++) {
        sprintf(hex_result + (i * 2), "%02X", result_binary[i]);
    }
    hex_result[result_size * 2] = '\0';
    
    free(ciphertext);
    free(result_binary);
    return hex_result;
}

// Decrypt a string
char* decrypt_string(const char *hex_string, const char *password, const char *paths) {
    // Convert hex string to binary
    size_t hex_len = strlen(hex_string);
    if (hex_len % 2 != 0 || hex_len < sizeof(header_t) * 2) {
        return NULL; // Invalid hex string
    }
    
    size_t binary_len = hex_len / 2;
    uint8_t *binary_data = malloc(binary_len);
    if (!binary_data) {
        return NULL;
    }
    
    for (size_t i = 0; i < binary_len; i++) {
        sscanf(hex_string + (i * 2), "%2hhx", &binary_data[i]);
    }
    
    // Extract header and ciphertext
    header_t *header = (header_t*)binary_data;
    uint8_t *ciphertext = binary_data + sizeof(header_t);
    size_t ciphertext_len = binary_len - sizeof(header_t);
    
    // Allocate memory for plaintext
    size_t max_plaintext_len = ciphertext_len - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    uint8_t *plaintext = malloc(max_plaintext_len + 1); // +1 for null terminator
    if (!plaintext) {
        free(binary_data);
        return NULL;
    }
    
    // Decrypt the ciphertext
    size_t plaintext_len;
    if (decrypt_blob(ciphertext, ciphertext_len, password,
                    (uint8_t*)paths, paths ? strlen(paths) : 0,
                    header, plaintext, &plaintext_len) != 0) {
        free(binary_data);
        free(plaintext);
        return NULL;
    }
    
    // Null-terminate the plaintext
    plaintext[plaintext_len] = '\0';
    
    free(binary_data);
    return (char*)plaintext;
}

// Helper function to convert paths/doubts to KDF parameters
void paths_to_kdf_params(const char *paths, uint8_t *mem_log2, uint8_t *ops, uint8_t *parallel) {
    if (!paths || !*paths) {
        // Default parameters
        *mem_log2 = 28;  // ~256MB
        *ops = 3;
        *parallel = 1;
        return;
    }
    
    // Calculate a hash of the paths
    uint8_t hash[32];
    crypto_generichash(hash, sizeof(hash), (const uint8_t*)paths, strlen(paths), NULL, 0);
    
    // Use the hash to derive KDF parameters
    // Higher doubt = more memory/time
    uint32_t doubt_level = 0;
    for (int i = 0; i < 4; i++) {
        doubt_level = (doubt_level << 8) | hash[i];
    }
    
    // Scale doubt level to reasonable parameters
    // Memory: 64MB to 512MB (26 to 29)
    *mem_log2 = 26 + (hash[0] % 4);
    
    // Operations: 2 to 5
    *ops = 2 + (hash[1] % 4);
    
    // Parallelism: 1 to 4
    *parallel = 1 + (hash[2] % 4);
}

// Main function for testing
int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        printf("Error initializing libsodium\n");
        return 1;
    }
    
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s encrypt <password> <message> [paths]\n", argv[0]);
        printf("  %s decrypt <password> <hex_data> [paths]\n", argv[0]);
        printf("  %s encrypt-file <password> <input_file> <output_file> [paths]\n", argv[0]);
        printf("  %s decrypt-file <password> <input_file> <output_file> [paths]\n", argv[0]);
        printf("  %s test\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "encrypt") == 0) {
        if (argc < 4) {
            printf("Error: Missing password or message\n");
            return 1;
        }
        
        const char *password = argv[2];
        const char *message = argv[3];
        const char *paths = (argc > 4) ? argv[4] : NULL;
        
        printf("Encrypting message...\n");
        char *encrypted = encrypt_string(message, password, paths);
        if (encrypted) {
            printf("%s\n", encrypted);
            free(encrypted);
            return 0;
        } else {
            printf("Encryption failed\n");
            return 1;
        }
    }
    
    if (strcmp(argv[1], "decrypt") == 0) {
        if (argc < 4) {
            printf("Error: Missing password or hex data\n");
            return 1;
        }
        
        const char *password = argv[2];
        const char *hex_data = argv[3];
        const char *paths = (argc > 4) ? argv[4] : NULL;
        
        printf("Decrypting message...\n");
        char *decrypted = decrypt_string(hex_data, password, paths);
        if (decrypted) {
            printf("%s\n", decrypted);
            free(decrypted);
            return 0;
        } else {
            printf("Decryption failed (wrong password or tampered data)\n");
            return 1;
        }
    }
    
    if (strcmp(argv[1], "encrypt-file") == 0) {
        if (argc < 5) {
            printf("Error: Missing parameters\n");
            return 1;
        }
        
        const char *password = argv[2];
        const char *input_file = argv[3];
        const char *output_file = argv[4];
        const char *paths = (argc > 5) ? argv[5] : NULL;
        
        if (encrypt_file(input_file, output_file, password, paths) == 0) {
            printf("File encrypted successfully: %s -> %s\n", input_file, output_file);
            return 0;
        } else {
            printf("File encryption failed\n");
            return 1;
        }
    }
    
    if (strcmp(argv[1], "decrypt-file") == 0) {
        if (argc < 5) {
            printf("Error: Missing parameters\n");
            return 1;
        }
        
        const char *password = argv[2];
        const char *input_file = argv[3];
        const char *output_file = argv[4];
        const char *paths = (argc > 5) ? argv[5] : NULL;
        
        if (decrypt_file(input_file, output_file, password, paths) == 0) {
            printf("File decrypted successfully: %s -> %s\n", input_file, output_file);
            return 0;
        } else {
            printf("File decryption failed\n");
            return 1;
        }
    }
    
    if (strcmp(argv[1], "test") == 0) {
        printf("=== Running LRS Encryption Tests ===\n\n");
        
        const char *test_message = "This is a test message for LRS encryption.";
        const char *password = "test_password";
        const char *paths = "path1,path2,doubt3";
        
        printf("Original message: %s\n", test_message);
        printf("Password: %s\n", password);
        printf("Paths/Doubts: %s\n\n", paths);
        
        // Test string encryption/decryption
        printf("Testing string encryption/decryption...\n");
        char *encrypted = encrypt_string(test_message, password, paths);
        if (!encrypted) {
            printf("✗ String encryption failed\n");
            return 1;
        }
        
        printf("Encrypted: %s\n", encrypted);
        
        char *decrypted = decrypt_string(encrypted, password, paths);
        if (!decrypted) {
            printf("✗ String decryption failed\n");
            free(encrypted);
            return 1;
        }
        
        printf("Decrypted: %s\n", decrypted);
        
        if (strcmp(test_message, decrypted) == 0) {
            printf("✓ String encryption/decryption SUCCESS\n\n");
        } else {
            printf("✗ String encryption/decryption FAILED\n\n");
        }
        
        free(encrypted);
        free(decrypted);
        
        // Test file encryption/decryption
        printf("Testing file encryption/decryption...\n");
        
        // Create test file
        FILE *test_file = fopen("test_file.txt", "w");
        if (!test_file) {
            printf("✗ Failed to create test file\n");
            return 1;
        }
        
        fprintf(test_file, "%s\n", test_message);
        fprintf(test_file, "Second line with special chars: !@#$%%^&*()\n");
        fclose(test_file);
        
        // Encrypt file
        if (encrypt_file("test_file.txt", "test_file.lrs", password, paths) != 0) {
            printf("✗ File encryption failed\n");
            return 1;
        }
        
        printf("✓ File encrypted successfully\n");
        
        // Decrypt file
        if (decrypt_file("test_file.lrs", "test_file_decrypted.txt", password, paths) != 0) {
            printf("✗ File decryption failed\n");
            return 1;
        }
        
        printf("✓ File decrypted successfully\n");
        
        // Compare original and decrypted files
        FILE *orig = fopen("test_file.txt", "rb");
        FILE *dec = fopen("test_file_decrypted.txt", "rb");
        
        if (!orig || !dec) {
            printf("✗ Failed to open files for comparison\n");
            if (orig) fclose(orig);
            if (dec) fclose(dec);
            return 1;
        }
        
        int same = 1;
        int c1, c2;
        
        while ((c1 = fgetc(orig)) != EOF && (c2 = fgetc(dec)) != EOF) {
            if (c1 != c2) {
                same = 0;
                break;
            }
        }
        
        if (same && fgetc(orig) == EOF && fgetc(dec) == EOF) {
            printf("✓ File content matches perfectly\n\n");
        } else {
            printf("✗ File content mismatch\n\n");
        }
        
        fclose(orig);
        fclose(dec);
        
        // Test wrong password
        printf("Testing decryption with wrong password...\n");
        char *wrong_decrypted = decrypt_string(encrypted, "wrong_password", paths);
        
        if (!wrong_decrypted) {
            printf("✓ Decryption with wrong password correctly failed\n");
        } else {
            printf("✗ Decryption with wrong password unexpectedly succeeded\n");
            free(wrong_decrypted);
        }
        
        // Test wrong paths
        printf("Testing decryption with wrong paths...\n");
        char *wrong_paths_decrypted = decrypt_string(encrypted, password, "wrong,paths");
        
        if (!wrong_paths_decrypted) {
            printf("✓ Decryption with wrong paths correctly failed\n");
        } else {
            printf("✓ Decryption with wrong paths succeeded (paths are only used as AAD)\n");
            free(wrong_paths_decrypted);
        }
        
        // Clean up test files
        remove("test_file.txt");
        remove("test_file.lrs");
        remove("test_file_decrypted.txt");
        
        printf("\nAll tests completed!\n");
        return 0;
    }
    
    printf("Error: Unknown command '%s'\n", argv[1]);
    return 1;
}