# LRS Encryption Implementation

## Overview

This is a secure, quantum-sane encryption implementation using libsodium. It replaces the custom cryptographic functions with industry-standard, vetted cryptographic primitives:

- **Key Derivation**: Argon2id (memory-hard KDF)
- **Encryption**: XChaCha20-Poly1305 (AEAD cipher)
- **Random Generation**: libsodium's secure random number generator

## Security Features

- **Memory-hard KDF**: Argon2id with configurable memory, operations, and parallelism parameters
- **Authenticated Encryption**: XChaCha20-Poly1305 provides both confidentiality and integrity
- **Versioned Header**: Includes magic bytes, version, KDF parameters, salt, and nonce
- **Associated Data**: Paths/doubts are used as authenticated associated data (AAD)
- **Secure Random Values**: Cryptographically secure random salt (16 bytes) and nonce (24 bytes)

## File Format

Encrypted files have the following structure:

```
header_t || ciphertext || authentication tag
```

Where `header_t` contains:

```c
typedef struct {
    char magic[4];             // "LRS1"
    uint8_t version;           // 1
    uint8_t kdf_mem_log2;      // Memory cost parameter (e.g., 28 => ~256MB)
    uint8_t kdf_ops;           // Time cost parameter (e.g., 3)
    uint8_t kdf_parallel;      // Parallelism parameter (e.g., 1)
    uint8_t reserved[3];       // Reserved for future use
    uint8_t salt[16];          // Random salt for KDF
    uint8_t nonce[24];         // Random nonce for XChaCha20-Poly1305
    uint8_t paths_hash[16];    // Optional hash of paths/doubts
} header_t;
```

## Usage

### Compilation

```bash
gcc -O2 -o lrs_encryption lrs_encryption.c -lsodium
```

### Command-line Interface

```
# Encrypt a message
./lrs_encryption encrypt <password> <message> [paths/doubts]

# Decrypt a message
./lrs_encryption decrypt <password> <hex_data> [paths/doubts]

# Encrypt a file
./lrs_encryption encrypt-file <password> <input_file> <output_file> [paths/doubts]

# Decrypt a file
./lrs_encryption decrypt-file <password> <input_file> <output_file> [paths/doubts]

# Run tests
./lrs_encryption test
```

### Paths/Doubts Usage

The paths/doubts parameter serves multiple purposes:

1. **Authentication**: Used as Associated Authenticated Data (AAD) in the AEAD cipher
2. **KDF Parameters**: Can influence the KDF parameters (higher doubt = more memory/time)
3. **Verification**: A hash of the paths/doubts is stored in the header for UI verification

## Security Recommendations

- **Key Size**: 32 bytes (256-bit), quantum-resistant with ~2^128 effort under Grover's algorithm
- **KDF Parameters**:
  - Memory: 256-512 MB for desktop/server; 64-128 MB for mobile
  - Operations: 2-3
  - Parallelism: 1-4 (match CPU cores conservatively)
- **Salt and Nonce**: Always use fresh random values for each encryption

## Implementation Notes

- The implementation uses libsodium's high-level API for simplicity and security
- All sensitive data is zeroed after use with `sodium_memzero()`
- The code rejects any authentication failures with no partial decryption
- No custom cryptographic primitives are used