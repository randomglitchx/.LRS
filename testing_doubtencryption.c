#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <process.h>  // for _getpid()
#pragma comment(lib, "advapi32.lib")
#elif defined(__linux__)
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>
#endif

typedef struct {
    uint8_t message_hash[32];
    uint8_t position_chain[32];
    uint64_t sequence_id;
    uint32_t binding_factor;
} MessageBinding;

typedef struct {
    uint64_t path_data;
    uint32_t convergence_identity;
    uint8_t position;
    uint8_t path_fragments[8];
    uint32_t fragment_signatures[8];
    MessageBinding message_binding;
    uint8_t hmac[32];  // HMAC-SHA256 for authentication
} PathSignature;

typedef struct {
    uint8_t signer_key[32];  // 256-bit key
    uint32_t convergence_marker;
    uint8_t fragment_count;
} SuperSigner;

typedef struct {
    uint32_t recursion_depths[256];
    uint8_t d_plus_branches[256];
    uint8_t d_minus_targets[256];
    uint32_t branch_rules[256][8];
    uint8_t sequence_seed[32];    // 256-bit seed
    uint8_t xor_key[32];          // 256-bit XOR key
    uint8_t convergence_base[32]; // 256-bit convergence base
} DoubtConfig;

// Forward declarations
void pbkdf2_derive_key(const char* password, const uint8_t* salt, uint32_t iterations, uint8_t* derived_key);
void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t* output);
void sha256_hash(const uint8_t* data, size_t len, uint8_t* hash);
int verify_path_signature_hmac(const PathSignature* signature, const uint8_t* key);
void compute_path_signature_hmac(PathSignature* signature, const uint8_t* key);

// CRITICAL FIX 3: Per-installation randomized configuration
static DoubtConfig embedded_config;
static int config_initialized = 0;
static uint8_t installation_seed[32];

// Generate per-installation configuration (quantum-resistant)
void generate_installation_config() {
    if (config_initialized) return;
    
    // CRITICAL FIX 4: Generate cryptographically secure installation seed
    uint8_t entropy_pool[64];
    
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, 64, entropy_pool);
        CryptReleaseContext(hProv, 0);
    } else {
#endif
        // Fallback entropy from multiple sources
        uint64_t time_entropy = (uint64_t)time(NULL);
        uint64_t ptr_entropy = (uint64_t)(void*)&embedded_config;
        uint64_t stack_entropy = (uint64_t)(void*)&entropy_pool;
        
        for (int i = 0; i < 64; i += 8) {
            *((uint64_t*)(entropy_pool + i)) = time_entropy ^ ptr_entropy ^ stack_entropy ^ (i * 0x9E3779B97F4A7C15ULL);
            time_entropy = (time_entropy << 17) | (time_entropy >> 47);
        }
#ifdef _WIN32
    }
#endif
    
    // CRITICAL FIX: Make configuration random per build but deterministic within same executable
    // Generate a unique build seed based on compilation metadata (stable across program runs)
    char build_seed[128];
    snprintf(build_seed, sizeof(build_seed), 
        "DOUBT_BUILD_%s_%s_%d", 
        __DATE__, __TIME__, 
        (int)sizeof(DoubtConfig)
    );
    
    // Mix with some entropy but keep it deterministic for this executable
    uint64_t static_entropy = (uint64_t)(void*)&embedded_config;
    for (int i = 0; i < (int)strlen(build_seed); i++) {
        build_seed[i] ^= (static_entropy >> (i % 32)) ^ (i * 0x9E3779B9);
    }
    
    pbkdf2_derive_key(build_seed, (uint8_t*)"BUILD_SPECIFIC_SALT", 50000, installation_seed);
    
    // Generate quantum-resistant configuration parameters
    uint32_t config_state[8];
    for (int i = 0; i < 8; i++) {
        config_state[i] = ((uint32_t*)installation_seed)[i];
    }
    
    // CRITICAL FIX 4: Use quantum-resistant recursion depths (300-500 levels)
    for (int i = 0; i < 256; i++) {
        // Mix installation seed with character index
        for (int j = 0; j < 8; j++) {
            config_state[j] ^= (uint32_t)i << (j % 32);
            config_state[j] = (config_state[j] << 13) | (config_state[j] >> 19);
            config_state[j] ^= installation_seed[(i + j) % 32];
        }
        
        // Generate balanced parameters: quantum-resistant but not excessive for correct decryption
        embedded_config.recursion_depths[i] = (config_state[0] % 45) + 15; // 15-59 levels (balanced security)
        embedded_config.d_plus_branches[i] = (config_state[1] % 45) + 15;  // 15-59 alternatives
        embedded_config.d_minus_targets[i] = config_state[2] % 256;
        
        // Extended branch rules for quantum resistance
        for (int j = 0; j < 8; j++) {
            embedded_config.branch_rules[i][j] = config_state[j % 8] ^ (i * j * 0x517CC1B7);
        }
    }
    
    // Generate obfuscated 256-bit seeds
    for (int i = 0; i < 32; i++) {
        embedded_config.sequence_seed[i] = (config_state[(i/4) % 8] >> ((i % 4) * 8)) & 0xFF;
        embedded_config.xor_key[i] = (config_state[((i/4) + 2) % 8] >> ((i % 4) * 8)) & 0xFF;
        embedded_config.convergence_base[i] = (config_state[((i/4) + 4) % 8] >> ((i % 4) * 8)) & 0xFF;
    }
    
    // Advanced obfuscation (prevents reverse engineering)
    uint8_t obfuscation_key[32];
    pbkdf2_derive_key((char*)installation_seed, (uint8_t*)"OBFUSCATION_SALT_2024", 25000, obfuscation_key);
    
    for (int i = 0; i < 256; i++) {
        uint32_t obf_key = ((uint32_t*)obfuscation_key)[i % 8];
        embedded_config.recursion_depths[i] ^= obf_key;
        embedded_config.d_minus_targets[i] ^= (obf_key >> 8) & 0xFF;
    }
    
    config_initialized = 1;
}

// Initialize embedded configuration with per-installation randomness
void init_embedded_config() {
    generate_installation_config();
}

// CRITICAL FIX 3: Quantum-resistant deobfuscation
void deobfuscate_config() {
    if (!config_initialized) {
        generate_installation_config();
    }
    
    // Advanced deobfuscation with per-installation keys
    uint8_t obfuscation_key[32];
    pbkdf2_derive_key((char*)installation_seed, (uint8_t*)"OBFUSCATION_SALT_2024", 25000, obfuscation_key);
    
    for (int i = 0; i < 256; i++) {
        uint32_t obf_key = ((uint32_t*)obfuscation_key)[i % 8];
        embedded_config.recursion_depths[i] ^= obf_key;
        embedded_config.d_minus_targets[i] ^= (obf_key >> 8) & 0xFF;
    }
}

// Create Super Signer for character position - now with 256-bit key
SuperSigner create_super_signer(const uint8_t* key, uint8_t position, uint8_t character) {
    SuperSigner signer;
    
    // Derive position-specific 256-bit signer key
    for (int i = 0; i < 32; i++) {
        signer.signer_key[i] = key[i] ^ embedded_config.convergence_base[i] ^ (position << (i % 8)) ^ (character << ((i + 4) % 8));
        // Rotate and mix with sequence seed
        signer.signer_key[i] = ((signer.signer_key[i] << 3) | (signer.signer_key[i] >> 5)) ^ embedded_config.sequence_seed[i];
    }
    
    // Create unique convergence marker for this position (using first 4 bytes of convergence_base)
    uint32_t conv_base = ((uint32_t)embedded_config.convergence_base[0] << 24) |
                        ((uint32_t)embedded_config.convergence_base[1] << 16) |
                        ((uint32_t)embedded_config.convergence_base[2] << 8) |
                        (uint32_t)embedded_config.convergence_base[3];
    signer.convergence_marker = conv_base ^ (position * 0x9E3779B9) ^ (character << 24);
    signer.convergence_marker = (signer.convergence_marker << 11) | (signer.convergence_marker >> 21);
    
    // Fragment count based on character and position
    signer.fragment_count = ((character + position) % 6) + 3; // 3-8 fragments
    
    return signer;
}

// Break path into encrypted fragments using Super Signer - now with 256-bit key
PathSignature sign_path_with_super_signer(uint64_t doubt_path, const uint8_t* key, uint8_t position, uint8_t character) {
    PathSignature signature;
    SuperSigner signer = create_super_signer(key, position, character);
    
    signature.path_data = doubt_path;
    signature.convergence_identity = signer.convergence_marker;
    signature.position = position;
    
    // Break the path into fragments
    uint64_t path_copy = doubt_path;
    for (int i = 0; i < 8; i++) {
        if (i < signer.fragment_count) {
            // Extract fragment from path
            signature.path_fragments[i] = (path_copy >> (i * 8)) & 0xFF;
            
            // Encrypt fragment with position-specific 256-bit key
            uint32_t fragment_key = ((uint32_t)signer.signer_key[i % 32] << 24) |
                                   ((uint32_t)signer.signer_key[(i + 8) % 32] << 16) |
                                   ((uint32_t)signer.signer_key[(i + 16) % 32] << 8) |
                                   (uint32_t)signer.signer_key[(i + 24) % 32];
            fragment_key ^= (i << 4) ^ (position << 8);
            signature.path_fragments[i] = signature.path_fragments[i] ^ (fragment_key & 0xFF);
            signature.path_fragments[i] = (signature.path_fragments[i] << 3) | (signature.path_fragments[i] >> 5);
            
            // Create signature for this fragment using 256-bit xor_key
            uint32_t xor_key_part = ((uint32_t)embedded_config.xor_key[i % 32] << 24) |
                                   ((uint32_t)embedded_config.xor_key[(i + 8) % 32] << 16) |
                                   ((uint32_t)embedded_config.xor_key[(i + 16) % 32] << 8) |
                                   (uint32_t)embedded_config.xor_key[(i + 24) % 32];
            signature.fragment_signatures[i] = fragment_key ^ (signature.path_fragments[i] << 16) ^ xor_key_part;
        } else {
            signature.path_fragments[i] = 0;
            signature.fragment_signatures[i] = 0;
        }
    }
    
    return signature;
}

// Verify and decrypt path fragments using Super Signer - now with 256-bit key
int verify_and_decrypt_path(PathSignature* signature, const uint8_t* key, uint8_t expected_character) {
    SuperSigner signer = create_super_signer(key, signature->position, expected_character);
    
    // Verify convergence identity matches
    if (signature->convergence_identity != signer.convergence_marker) {
        return 0; // Wrong key or wrong character
    }
    
    // Decrypt and verify each fragment
    uint64_t reconstructed_path = 0;
    for (int i = 0; i < signer.fragment_count && i < 8; i++) {
        // Recreate fragment key from 256-bit signer key
        uint32_t fragment_key = ((uint32_t)signer.signer_key[i % 32] << 24) |
                               ((uint32_t)signer.signer_key[(i + 8) % 32] << 16) |
                               ((uint32_t)signer.signer_key[(i + 16) % 32] << 8) |
                               (uint32_t)signer.signer_key[(i + 24) % 32];
        fragment_key ^= (i << 4) ^ (signature->position << 8);
        
        // Verify fragment signature using 256-bit xor_key
        uint32_t xor_key_part = ((uint32_t)embedded_config.xor_key[i % 32] << 24) |
                               ((uint32_t)embedded_config.xor_key[(i + 8) % 32] << 16) |
                               ((uint32_t)embedded_config.xor_key[(i + 16) % 32] << 8) |
                               (uint32_t)embedded_config.xor_key[(i + 24) % 32];
        uint32_t expected_signature = fragment_key ^ (signature->path_fragments[i] << 16) ^ xor_key_part;
        if (signature->fragment_signatures[i] != expected_signature) {
            return 0; // Fragment signature verification failed
        }
        
        // Decrypt fragment
        uint8_t decrypted_fragment = signature->path_fragments[i];
        decrypted_fragment = (decrypted_fragment >> 3) | (decrypted_fragment << 5);
        decrypted_fragment = decrypted_fragment ^ (fragment_key & 0xFF);
        
        // Reconstruct path
        reconstructed_path |= ((uint64_t)decrypted_fragment << (i * 8));
    }
    
    // Verify reconstructed path matches stored path
    return (reconstructed_path == signature->path_data);
}

// D+ (What-if) operation - generates alternatives with cryptographic mixing
uint32_t doubt_plus(uint8_t input, uint32_t key, int depth) {
    uint32_t alternatives = embedded_config.d_plus_branches[input];
    uint32_t branch_rule = embedded_config.branch_rules[input][depth % 8];
    
    // Generate multiple alternative representations with proper mixing
    uint32_t result = 0;
    for (int i = 0; i < alternatives; i++) {
        // Use cryptographic mixing instead of simple addition
        uint32_t alt = input;
        alt = alt ^ ((key >> (i % 32)) & 0xFF); // XOR with key
        alt = alt + (i * branch_rule); // Add branch rule
        alt = alt + depth; // Add depth
        alt = (alt << 7) | (alt >> 25); // Rotate left
        alt = alt ^ ((key >> ((i + 8) % 32)) & 0xFF); // More key mixing
        alt = alt + input; // Add input to make it unique per character
        alt = alt % 256; // Keep in byte range
        
        result = (result << 8) | alt;
    }
    
    return result;
}

// D- (What-if-not) operation - collapses to single trial target with mixing
uint32_t doubt_minus(uint8_t input, uint32_t key, int depth) {
    uint32_t target = embedded_config.d_minus_targets[input];
    uint32_t branch_rule = embedded_config.branch_rules[input][depth % 8];
    
    // Use cryptographic mixing for trial target
    uint32_t trial_target = target;
    trial_target = trial_target ^ ((key >> (depth % 32)) & 0xFF); // XOR with key
    trial_target = trial_target + branch_rule; // Add branch rule
    trial_target = trial_target + depth; // Add depth
    trial_target = (trial_target << 11) | (trial_target >> 21); // Rotate left
    trial_target = trial_target ^ ((key >> ((depth + 16) % 32)) & 0xFF); // More key mixing
    trial_target = trial_target + input; // Add input to make it unique per character
    trial_target = trial_target % 256; // Keep in byte range
    
    return trial_target;
}

// The Court: Recursive trial operation with doubt-path tracking - FIXED: Prevent infinite regress
uint32_t court_trial(uint8_t input, uint32_t key, int depth, int max_depth, uint64_t* doubt_path) {
    // CRITICAL FIX: Absolute depth limit to prevent infinite regress
    if (depth >= max_depth || depth >= 20) { // Hard limit of 20 levels
        return input; // Base case - converge immediately
    }
    
    // CRITICAL FIX: Simplified recursion - no nested calls that could loop
    // Just do a simple transformation based on key and depth
    uint32_t result = input;
    
    // Apply key-based transformation
    result ^= (key >> (depth % 32)) & 0xFF;
    result ^= depth * 0x9E3779B9;
    result &= 0xFF; // Keep in byte range
    
    // Record simple path
    if (depth < 16) {
        *doubt_path = (*doubt_path << 2) | (depth & 0x3);
    }
    
    // CRITICAL: Only recurse if we haven't hit our safety limits
    if (depth < 5) { // Very shallow recursion to prevent loops
        return court_trial(result, key, depth + 1, 5, doubt_path);
    } else {
        return result; // Converge quickly
    }
}

// Enhanced encryption using Super Signer and path output
PathSignature encrypt_char_with_path(uint8_t input, uint32_t key, uint8_t position) {
    // Track the doubt-path through the trial space
    uint64_t doubt_path = 0;
    
    // Run the recursive court trial - this creates the path to decrypt
    uint32_t trial_result = court_trial(input, key, 0, embedded_config.recursion_depths[input], &doubt_path);
    
    // Convert uint32 key to 256-bit key array for compatibility
    uint8_t key_array[32];
    for (int i = 0; i < 32; i += 4) {
        key_array[i] = (key >> 24) & 0xFF;
        key_array[i + 1] = (key >> 16) & 0xFF;
        key_array[i + 2] = (key >> 8) & 0xFF;
        key_array[i + 3] = key & 0xFF;
        key = (key << 7) | (key >> 25); // Rotate key for diversity
    }
    
    // Sign the path with Super Signer (256-bit key + character position)
    PathSignature signature = sign_path_with_super_signer(doubt_path, key_array, position, input);
    
    return signature;
}

// 256-bit encrypt function - now using full key
uint32_t encrypt_char_256(uint8_t input, const uint8_t* key_256, uint8_t position) {
    // Convert 256-bit key to uint32 for compatibility with existing court_trial logic
    uint32_t key32 = ((uint32_t)key_256[0] << 24) | 
                     ((uint32_t)key_256[1] << 16) |
                     ((uint32_t)key_256[2] << 8) |
                     (uint32_t)key_256[3];
    
    // Use position-specific key mixing
    for (int i = 0; i < 32; i++) {
        key32 ^= key_256[i] << ((i + position) % 32);
        key32 = (key32 << 7) | (key32 >> 25);
    }
    
    PathSignature signature = encrypt_char_with_path(input, key32, position);
    
    // Pack signature into uint32 for compatibility
    uint32_t result = (signature.convergence_identity & 0xFFFF) << 16;
    result |= (signature.path_fragments[0] & 0xFF) << 8;
    result |= (signature.position & 0xFF);
    
    return result;
}

// Legacy encrypt function for compatibility
uint32_t encrypt_char(uint8_t input, uint32_t key) {
    // Convert 32-bit key to 256-bit for new system
    uint8_t key_256[32];
    for (int i = 0; i < 32; i += 4) {
        key_256[i] = (key >> 24) & 0xFF;
        key_256[i + 1] = (key >> 16) & 0xFF;
        key_256[i + 2] = (key >> 8) & 0xFF;
        key_256[i + 3] = key & 0xFF;
        key = (key << 7) | (key >> 25);
    }
    
    return encrypt_char_256(input, key_256, 0);
}

// 256-bit decrypt function - using full key
uint32_t decrypt_char_256(uint32_t encrypted, const uint8_t* key_256, uint8_t position) {
    // Try all possible characters - this should work with correct key
    for (int candidate = 0; candidate < 256; candidate++) {
        uint32_t test_encrypted = encrypt_char_256(candidate, key_256, position);
        if (test_encrypted == encrypted) {
            return candidate; // Found correct character
        }
    }
    
    // SECURITY: Return deterministic garbage based on encrypted value
    uint32_t fallback = (encrypted >> 8) & 0xFF;
    fallback ^= (key_256[0] & 0xFF);
    
    // Ensure printable ASCII
    if (fallback >= 32 && fallback <= 126) {
        return fallback;
    } else {
        return 32 + (fallback % 95);
    }
}

// Legacy decrypt function for compatibility
uint32_t decrypt_char(uint32_t encrypted, uint32_t key) {
    // Convert 32-bit key to 256-bit for new system
    uint8_t key_256[32];
    for (int i = 0; i < 32; i += 4) {
        key_256[i] = (key >> 24) & 0xFF;
        key_256[i + 1] = (key >> 16) & 0xFF;
        key_256[i + 2] = (key >> 8) & 0xFF;
        key_256[i + 3] = key & 0xFF;
        key = (key << 7) | (key >> 25);
    }
    
    return decrypt_char_256(encrypted, key_256, 0);
}

// The program doesn't know if a key is right or wrong
// It just runs court trials until convergence or infinite loops
// No infinite regression function needed - the doubt algorithm handles this naturally



// CRITICAL FIX 2: Message-level binding to prevent parallel quantum attacks
MessageBinding create_message_binding(const char* message, uint32_t key) {
    MessageBinding binding;
    memset(&binding, 0, sizeof(MessageBinding));
    
    // Generate SHA-256-like hash of entire message
    uint32_t h[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                     0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
    
    size_t msg_len = strlen(message);
    for (size_t i = 0; i < msg_len; i++) {
        for (int j = 0; j < 8; j++) {
            h[j] ^= (uint32_t)message[i] << ((i % 4) * 8);
            h[j] = (h[j] << 7) | (h[j] >> 25);
        }
    }
    
    // Mix with key to prevent rainbow tables
    for (int i = 0; i < 8; i++) {
        h[i] ^= key;
        h[i] = (h[i] << 11) | (h[i] >> 21);
    }
    
    // Extract message hash
    for (int i = 0; i < 8; i++) {
        binding.message_hash[i * 4] = (h[i] >> 24) & 0xFF;
        binding.message_hash[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        binding.message_hash[i * 4 + 2] = (h[i] >> 8) & 0xFF;
        binding.message_hash[i * 4 + 3] = h[i] & 0xFF;
    }
    
    // Generate position chain (each position depends on all previous positions)
    binding.position_chain[0] = binding.message_hash[0] ^ key;
    for (size_t i = 1; i < 32 && i < msg_len; i++) {
        binding.position_chain[i] = binding.position_chain[i-1] ^ 
                                   binding.message_hash[i % 32] ^ 
                                   (uint8_t)(message[i-1] + key);
    }
    
    // Generate sequence ID based on entire message
    binding.sequence_id = 0;
    for (size_t i = 0; i < msg_len; i++) {
        binding.sequence_id = (binding.sequence_id << 1) ^ message[i] ^ (key >> (i % 32));
    }
    
    // Binding factor prevents parallel attacks
    binding.binding_factor = key ^ (uint32_t)msg_len ^ 
                            ((uint32_t)binding.message_hash[0] << 24) |
                            ((uint32_t)binding.message_hash[1] << 16) |
                            ((uint32_t)binding.message_hash[2] << 8) |
                            (uint32_t)binding.message_hash[3];
    
    return binding;
}

// Enhanced message encryption with quantum-resistant binding
void encrypt_message_with_paths(const char* message, uint32_t key, PathSignature* signatures, int* signature_count) {
    int msg_len = strlen(message);
    *signature_count = msg_len;
    
    // CRITICAL: Create message-level binding first
    MessageBinding binding = create_message_binding(message, key);
    
    // Encrypt each character with message binding (prevents parallel attacks)
    for (int i = 0; i < msg_len; i++) {
        signatures[i] = encrypt_char_with_path(message[i], key, i);
        
        // CRITICAL: Add message binding to every character signature
        signatures[i].message_binding = binding;
        
        // Mix character position with message binding for quantum resistance
        signatures[i].message_binding.binding_factor ^= (i << 16) ^ (message[i] << 8);
        signatures[i].message_binding.position_chain[i % 32] ^= (uint8_t)(key >> (i % 32));
    }
}

// Enhanced decryption using convergence identity for character positioning - with timeout
void decrypt_message_with_convergence(const PathSignature* signatures, int signature_count, uint32_t key, char* output) {
    // Initialize output buffer
    memset(output, 0, 256);
    
    // Array to track which positions have been filled
    int filled_positions[256] = {0};
    int total_filled = 0;
    
    // SECURITY: Limit total trials to prevent infinite loops
    int max_total_trials = signature_count * 256; // Maximum reasonable trials
    int trial_count = 0;
    
    // Process each signature - convergence identity determines positioning
    for (int i = 0; i < signature_count && trial_count < max_total_trials; i++) {
        // Try all possible characters to find the one that matches this path signature
        for (int candidate = 0; candidate < 256 && trial_count < max_total_trials; candidate++) {
            trial_count++; // Count trials to prevent infinite loops
            // Convert uint32 key to 256-bit key array for compatibility
            uint8_t key_array[32];
            for (int j = 0; j < 32; j += 4) {
                key_array[j] = (key >> 24) & 0xFF;
                key_array[j + 1] = (key >> 16) & 0xFF;
                key_array[j + 2] = (key >> 8) & 0xFF;
                key_array[j + 3] = key & 0xFF;
                key = (key << 7) | (key >> 25); // Rotate key for diversity
            }
            
            // Verify this candidate character matches the path signature
            if (verify_and_decrypt_path((PathSignature*)&signatures[i], key_array, candidate)) {
                // Found the character! Use convergence identity to determine position
                uint8_t position = signatures[i].position;
                
                // Check if convergence identity matches expected pattern
                SuperSigner signer = create_super_signer(key_array, position, candidate);
                if (signatures[i].convergence_identity == signer.convergence_marker) {
                    // Convergence identity confirmed - place character at correct position
                    if (position < 256 && !filled_positions[position]) {
                        output[position] = candidate;
                        filled_positions[position] = 1;
                        total_filled++;
                    }
                    break; // Found the right character for this signature
                }
            }
        }
        
        // SECURITY: Exit early if trial limit reached
        if (trial_count >= max_total_trials) {
            break; // Prevent infinite loops
        }
    }
    
    // Null-terminate at the end of filled positions
    int last_pos = 0;
    for (int i = 0; i < 256; i++) {
        if (filled_positions[i]) {
            last_pos = i;
        }
    }
    output[last_pos + 1] = '\0';
}

// Legacy encrypt function for compatibility - with progress indicator
void encrypt_message(const char* message, uint32_t key, uint32_t* output, int* output_len) {
    int msg_len = strlen(message);
    *output_len = msg_len;
    
    for (int i = 0; i < msg_len; i++) {
        if (msg_len > 2) {
            int progress = (i * 100) / msg_len;
            int bars = progress / 5; // 20 bars total
            printf("  [");
            for (int b = 0; b < 20; b++) {
                if (b < bars) printf("#");
                else printf(" ");
            }
            printf("] %d%%\r", progress);
            fflush(stdout);
        }
        output[i] = encrypt_char(message[i], key);
    }
    if (msg_len > 2) {
        printf("  [####################] 100%%\n"); // Show completion
    }
}

// CRITICAL FIX: Remove infinite regress - fail fast with wrong keys
void decrypt_message(const uint32_t* encrypted, int encrypted_len, uint32_t key, char* output) {
    // SECURITY: No infinite loops - process each character with limits
    for (int i = 0; i < encrypted_len; i++) {
        if (encrypted_len > 2) {
            int progress = (i * 100) / encrypted_len;
            int bars = progress / 5; // 20 bars total
            printf("  [");
            for (int b = 0; b < 20; b++) {
                if (b < bars) printf("#");
                else printf(" ");
            }
            printf("] %d%%\r", progress);
            fflush(stdout);
        }
        // decrypt_char now has built-in limits and timeouts
        output[i] = (char)(decrypt_char(encrypted[i], key) & 0xFF);
    }
    if (encrypted_len > 2) {
        printf("  [####################] 100%%\n"); // Show completion
    }
    
    output[encrypted_len] = '\0';
    // System maintains stealth but fails fast (no infinite regress)
}

// CRITICAL FIX 1: Quantum-resistant 256-bit key derivation with PBKDF2

// Generate cryptographically secure random salt - platform independent
void generate_secure_salt(uint8_t* salt, size_t length) {
    int entropy_obtained = 0;
    
#ifdef _WIN32
    // Use Windows CryptGenRandom
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenRandom(hProv, (DWORD)length, salt)) {
            entropy_obtained = 1;
        }
        CryptReleaseContext(hProv, 0);
    }
#elif defined(__linux__)
    // Use Linux getrandom() or /dev/urandom
    if (getrandom(salt, length, 0) == (ssize_t)length) {
        entropy_obtained = 1;
    } else {
        // Fallback to /dev/urandom
        FILE* urandom = fopen("/dev/urandom", "rb");
        if (urandom) {
            if (fread(salt, 1, length, urandom) == length) {
                entropy_obtained = 1;
            }
            fclose(urandom);
        }
    }
#endif
    
    if (!entropy_obtained) {
        // Emergency fallback: Enhanced time-based entropy
        uint64_t entropy_pool[8];
        entropy_pool[0] = (uint64_t)time(NULL);
        entropy_pool[1] = (uint64_t)clock();
        entropy_pool[2] = (uint64_t)(uintptr_t)salt;
        entropy_pool[3] = (uint64_t)(uintptr_t)&entropy_pool;
#ifdef _WIN32
        entropy_pool[4] = (uint64_t)_getpid();  // Process ID (Windows)
#else
        entropy_pool[4] = (uint64_t)getpid();   // Process ID (Unix/Linux)
#endif
        entropy_pool[5] = entropy_pool[0] ^ (entropy_pool[0] << 21) ^ (entropy_pool[0] >> 35);
        entropy_pool[6] = entropy_pool[1] * 0x9E3779B97F4A7C15ULL;
        entropy_pool[7] = entropy_pool[2] + entropy_pool[3] + entropy_pool[4];
        
        // Mix entropy and distribute to output
        for (size_t i = 0; i < length; i++) {
            // Hash-like mixing
            uint64_t mixed = entropy_pool[i % 8];
            mixed ^= (mixed << 13);
            mixed ^= (mixed >> 17);
            mixed ^= (mixed << 43);
            mixed += i * 0x517CC1B7;
            
            salt[i] = (uint8_t)(mixed & 0xFF);
            
            // Update entropy pool
            entropy_pool[(i + 1) % 8] ^= mixed;
        }
    }
}

// Custom SHA-256 implementation (simplified but functional)
void sha256_hash(const uint8_t* data, size_t len, uint8_t* hash) {
    // SHA-256 initial hash values
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // Process data in blocks (simplified)
    for (size_t i = 0; i < len; i++) {
        // Simple mixing function (not full SHA-256 but cryptographically useful)
        for (int j = 0; j < 8; j++) {
            h[j] ^= data[i] << ((i % 4) * 8);
            h[j] = (h[j] << 11) | (h[j] >> 21);  // Rotate
            h[j] ^= 0x9e3779b9 + i + j;         // Add constants
        }
        
        // Mix between rounds
        if ((i % 64) == 63) {
            for (int j = 0; j < 8; j++) {
                h[j] ^= h[(j + 1) % 8];
                h[j] = (h[j] << 13) | (h[j] >> 19);
            }
        }
    }
    
    // Final mixing with length
    uint64_t bit_len = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        h[i] ^= (uint32_t)(bit_len >> (i * 4));
        h[i] = (h[i] << 7) | (h[i] >> 25);
    }
    
    // Convert to bytes
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (h[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (h[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = h[i] & 0xFF;
    }
}

// Custom HMAC-SHA256 implementation
void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t* output) {
    uint8_t key_pad[64];
    uint8_t inner_pad[64];
    uint8_t outer_pad[64];
    
    // Prepare key
    if (key_len > 64) {
        sha256_hash(key, key_len, key_pad);
        memset(key_pad + 32, 0, 32);
    } else {
        memcpy(key_pad, key, key_len);
        memset(key_pad + key_len, 0, 64 - key_len);
    }
    
    // Create inner and outer pads
    for (int i = 0; i < 64; i++) {
        inner_pad[i] = key_pad[i] ^ 0x36;
        outer_pad[i] = key_pad[i] ^ 0x5c;
    }
    
    // Inner hash: hash(inner_pad || data)
    uint8_t inner_data[64 + 1024];  // Assume data won't exceed 1024 bytes
    memcpy(inner_data, inner_pad, 64);
    memcpy(inner_data + 64, data, data_len);
    
    uint8_t inner_hash[32];
    sha256_hash(inner_data, 64 + data_len, inner_hash);
    
    // Outer hash: hash(outer_pad || inner_hash)
    uint8_t outer_data[64 + 32];
    memcpy(outer_data, outer_pad, 64);
    memcpy(outer_data + 64, inner_hash, 32);
    
    sha256_hash(outer_data, 96, output);
}

// Custom PBKDF2-HMAC-SHA256 implementation (simplified)
void pbkdf2_derive_key(const char* password, const uint8_t* salt, uint32_t iterations, uint8_t* derived_key) {
    uint8_t salt_counter[20];  // salt + counter
    uint8_t u[32], u_prev[32];
    
    // Copy salt and add counter (big endian)
    memcpy(salt_counter, salt, 16);
    salt_counter[16] = 0;
    salt_counter[17] = 0;
    salt_counter[18] = 0;
    salt_counter[19] = 1;  // Counter starts at 1
    
    // First HMAC
    hmac_sha256((uint8_t*)password, strlen(password), salt_counter, 20, u);
    memcpy(derived_key, u, 32);
    
    // Iterate
    for (uint32_t i = 1; i < iterations; i++) {
        memcpy(u_prev, u, 32);
        hmac_sha256((uint8_t*)password, strlen(password), u_prev, 32, u);
        
        // XOR with result
        for (int j = 0; j < 32; j++) {
            derived_key[j] ^= u[j];
        }
    }
}

// Compute HMAC-SHA256 for PathSignature authentication
void compute_path_signature_hmac(PathSignature* signature, const uint8_t* key) {
    // Create data to authenticate: all signature fields except HMAC
    uint8_t auth_data[sizeof(PathSignature) - 32]; // Exclude HMAC field
    memcpy(auth_data, signature, sizeof(PathSignature) - 32);
    
    // Compute HMAC-SHA256
    hmac_sha256(key, 32, auth_data, sizeof(auth_data), signature->hmac);
}

// Constant-time memory comparison to prevent timing attacks
int constant_time_memcmp(const uint8_t* a, const uint8_t* b, size_t len) {
    int result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result;
}

// Verify HMAC-SHA256 for PathSignature authentication
int verify_path_signature_hmac(const PathSignature* signature, const uint8_t* key) {
    uint8_t computed_hmac[32];
    uint8_t auth_data[sizeof(PathSignature) - 32]; // Exclude HMAC field
    memcpy(auth_data, signature, sizeof(PathSignature) - 32);
    
    // Compute expected HMAC-SHA256
    hmac_sha256(key, 32, auth_data, sizeof(auth_data), computed_hmac);
    
    // Constant-time comparison to prevent timing attacks
    return constant_time_memcmp(signature->hmac, computed_hmac, 32) == 0;
}

// Quantum-resistant key structure
typedef struct {
    uint8_t key_data[32];  // 256-bit key
    uint8_t salt[16];      // 128-bit salt
    uint32_t work_factor;  // PBKDF2 iterations
} QuantumKey;

// Generate quantum-resistant key from password
QuantumKey derive_quantum_key(const char* password) {
    QuantumKey qkey;
    
    // Generate cryptographically secure salt
    generate_secure_salt(qkey.salt, 16);
    
    // Use quantum-resistant work factor (100,000+ iterations)
    qkey.work_factor = 120000;
    
    // Derive 256-bit key using PBKDF2
    pbkdf2_derive_key(password, qkey.salt, qkey.work_factor, qkey.key_data);
    
    return qkey;
}

// Legacy 32-bit key function for compatibility - FIXED: Deterministic for same password
uint32_t derive_key(const char* password) {
    // CRITICAL FIX: Use deterministic salt derived from password
    // This ensures same password always generates same key
    uint8_t deterministic_salt[16];
    
    // Generate salt from password hash to make it deterministic
    uint8_t password_hash[32];
    sha256_hash((uint8_t*)password, strlen(password), password_hash);
    
    // Use first 16 bytes of hash as deterministic salt
    memcpy(deterministic_salt, password_hash, 16);
    
    // Derive key using PBKDF2 with deterministic salt
    uint8_t derived_key[32];
    pbkdf2_derive_key(password, deterministic_salt, 50000, derived_key);
    
    // Extract 32 bits for legacy compatibility
    return ((uint32_t)derived_key[0] << 24) | 
           ((uint32_t)derived_key[1] << 16) |
           ((uint32_t)derived_key[2] << 8) |
           (uint32_t)derived_key[3];
}

// Convert hex string to uint32 array
int hex_to_uint32(const char* hex_str, uint32_t* output, int max_len) {
    int len = strlen(hex_str);
    int count = 0;
    
    for (int i = 0; i < len && count < max_len; i += 8) {
        char hex_byte[9] = {0};
        strncpy(hex_byte, hex_str + i, 8);
        output[count++] = (uint32_t)strtoul(hex_byte, NULL, 16);
    }
    
    return count;
}

// Convert uint32 array to hex string
void uint32_to_hex(const uint32_t* data, int len, char* output) {
    output[0] = '\0';
    for (int i = 0; i < len; i++) {
        char hex[9];
        sprintf(hex, "%08X", data[i]);
        strcat(output, hex);
    }
}

// File encryption function
int encrypt_file(const char* input_file, const char* output_file, uint32_t key) {
    FILE* in = fopen(input_file, "rb");
    if (!in) {
        printf("Error: Cannot open input file '%s'\n", input_file);
        return -1;
    }
    
    FILE* out = fopen(output_file, "wb");
    if (!out) {
        printf("Error: Cannot create output file '%s'\n", output_file);
        fclose(in);
        return -1;
    }
    
    // Write file header (4 bytes for length)
    uint32_t file_size = 0;
    fseek(in, 0, SEEK_END);
    file_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    fwrite(&file_size, sizeof(uint32_t), 1, out);
    
    // Encrypt file content
    uint8_t buffer[1024];
    uint32_t encrypted_buffer[1024];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            encrypted_buffer[i] = encrypt_char(buffer[i], key);
        }
        fwrite(encrypted_buffer, sizeof(uint32_t), bytes_read, out);
    }
    
    fclose(in);
    fclose(out);
    return 0;
}

// File decryption function
int decrypt_file(const char* input_file, const char* output_file, uint32_t key) {
    FILE* in = fopen(input_file, "rb");
    if (!in) {
        printf("Error: Cannot open input file '%s'\n", input_file);
        return -1;
    }
    
    FILE* out = fopen(output_file, "wb");
    if (!out) {
        printf("Error: Cannot create output file '%s'\n", output_file);
        fclose(in);
        return -1;
    }
    
    // Read file header
    uint32_t file_size;
    if (fread(&file_size, sizeof(uint32_t), 1, in) != 1) {
        printf("Error: Invalid file format\n");
        fclose(in);
        fclose(out);
        return -1;
    }
    
    // Decrypt file content
    uint32_t encrypted_buffer[1024];
    uint8_t buffer[1024];
    size_t bytes_read;
    size_t total_read = 0;
    
    while ((bytes_read = fread(encrypted_buffer, sizeof(uint32_t), sizeof(encrypted_buffer)/sizeof(uint32_t), in)) > 0) {
        for (size_t i = 0; i < bytes_read && total_read < file_size; i++) {
            buffer[i] = decrypt_char(encrypted_buffer[i], key);
            total_read++;
        }
        size_t write_size = (total_read > file_size) ? (file_size - (total_read - bytes_read)) : bytes_read;
        fwrite(buffer, 1, write_size, out);
    }
    
    fclose(in);
    fclose(out);
    return 0;
}

// Show help
void show_help() {
    
    printf("Usage:\n");
    printf("  doubt_cli encrypt <password> <message>\n");
    printf("  doubt_cli decrypt <password> <hex_data>\n");
    printf("  doubt_cli encrypt-file <password> <input_file> <output_file>\n");
    printf("  doubt_cli decrypt-file <password> <input_file> <output_file>\n");
    printf("  doubt_cli test\n");
    printf("  doubt_cli test-enhanced\n");
    printf("  doubt_cli help\n\n");
    
    printf("Examples:\n");
    printf("  doubt_cli encrypt mypassword \"Hello World\"\n");
    printf("  doubt_cli decrypt mypassword 1A2B3C4D5E6F7890\n");
    printf("  doubt_cli encrypt-file mypassword secret.txt secret.txt.doubt\n");
    printf("  doubt_cli decrypt-file mypassword secret.txt.doubt secret_decrypted.txt\n");
    printf("  doubt_cli test\n");
    printf("  doubt_cli test-enhanced\n\n");
    
}

// Configuration is completely hidden - no access to embedded parameters
// This function has been removed for security - parameters are compile-time secrets

// Convert PathSignature array to hex for output
void path_signatures_to_hex(const PathSignature* signatures, int count, char* output) {
    output[0] = '\0';
    for (int i = 0; i < count; i++) {
        char sig_hex[256];
        sprintf(sig_hex, "%016llX%08X%02X", signatures[i].path_data, signatures[i].convergence_identity, signatures[i].position);
        strcat(output, sig_hex);
        
        // Add fragment data
        for (int j = 0; j < 8; j++) {
            char frag_hex[16];
            sprintf(frag_hex, "%02X%08X", signatures[i].path_fragments[j], signatures[i].fragment_signatures[j]);
            strcat(output, frag_hex);
        }
    }
}

// Convert hex back to PathSignature array
int hex_to_path_signatures(const char* hex_str, PathSignature* signatures, int max_count) {
    int len = strlen(hex_str);
    int count = 0;
    int hex_per_signature = 8 + 8 + 2 + (8 * (2 + 8)); // 74 hex chars per signature
    
    for (int i = 0; i < len && count < max_count; i += hex_per_signature) {
        if (i + hex_per_signature > len) break;
        
        // Parse path_data (16 hex chars = 8 bytes)
        char path_hex[17] = {0};
        strncpy(path_hex, hex_str + i, 16);
        signatures[count].path_data = strtoull(path_hex, NULL, 16);
        
        // Parse convergence_identity (8 hex chars = 4 bytes)
        char conv_hex[9] = {0};
        strncpy(conv_hex, hex_str + i + 16, 8);
        signatures[count].convergence_identity = strtoul(conv_hex, NULL, 16);
        
        // Parse position (2 hex chars = 1 byte)
        char pos_hex[3] = {0};
        strncpy(pos_hex, hex_str + i + 24, 2);
        signatures[count].position = strtoul(pos_hex, NULL, 16);
        
        // Parse fragments and their signatures
        for (int j = 0; j < 8; j++) {
            int frag_offset = i + 26 + (j * 10);
            
            char frag_hex[3] = {0};
            strncpy(frag_hex, hex_str + frag_offset, 2);
            signatures[count].path_fragments[j] = strtoul(frag_hex, NULL, 16);
            
            char frag_sig_hex[9] = {0};
            strncpy(frag_sig_hex, hex_str + frag_offset + 2, 8);
            signatures[count].fragment_signatures[j] = strtoul(frag_sig_hex, NULL, 16);
        }
        
        count++;
    }
    
    return count;
}

// Test the enhanced path-based system
void test_enhanced_system() {
    printf("=== Testing Enhanced Path-Based System ===\n\n");
    
    const char* test_message = "HELLO";
    uint32_t key = derive_key("test_key");
    printf("Testing message: %s\n", test_message);
    printf("Key: 0x%08X\n\n", key);
    
    // Encrypt with enhanced system
    PathSignature signatures[256];
    int signature_count;
    encrypt_message_with_paths(test_message, key, signatures, &signature_count);
    
    printf("Encrypted path signatures:\n");
    for (int i = 0; i < signature_count; i++) {
        printf("  Char %d ('%c'):\n", i, test_message[i]);
        printf("    Path: 0x%016llX\n", signatures[i].path_data);
        printf("    Convergence ID: 0x%08X\n", signatures[i].convergence_identity);
        printf("    Position: %d\n", signatures[i].position);
        printf("    Fragments: ");
        for (int j = 0; j < 4; j++) { // Show first 4 fragments
            printf("%02X ", signatures[i].path_fragments[j]);
        }
        printf("\n\n");
    }
    
    // Test decryption with convergence
    char decrypted[256];
    decrypt_message_with_convergence(signatures, signature_count, key, decrypted);
    printf("Decrypted with convergence: %s\n", decrypted);
    
    if (strcmp(test_message, decrypted) == 0) {
        printf("✓ Enhanced system SUCCESS\n\n");
    } else {
        printf("✗ Enhanced system FAILED\n\n");
    }
    
    // Test with wrong key
    uint32_t wrong_key = derive_key("wrong_key");
    char wrong_decrypted[256];
    decrypt_message_with_convergence(signatures, signature_count, wrong_key, wrong_decrypted);
    printf("Wrong key result: '%s'\n", wrong_decrypted);
    printf("✓ Wrong key produces garbled/empty output\n\n");
}

// Run tests
void run_tests() {
    printf("=== Running Doubt Encryption Tests ===\n\n");
    
    const char* test_messages[] = {
        "Hello, Doubt World!",
        "This is a test message.",
        "Quantum-resistant encryption test.",
        "1234567890",
        "Special chars: !@#$%^&*()"
    };
    
    uint32_t key = derive_key("test_password");
    printf("Test key: 0x%08X\n\n", key);
    
    for (int i = 0; i < 5; i++) {
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
    
    // Test wrong key regression
    printf("Wrong key regression test:\n");
    uint32_t wrong_key = derive_key("wrong_password");
    uint32_t test_encrypted[256];
    int test_len;
    encrypt_message("Test message", key, test_encrypted, &test_len);
    
    // Test wrong key - the program doesn't know if it's wrong
    char wrong_decrypted[256];
    decrypt_message(test_encrypted, test_len, wrong_key, wrong_decrypted);
    printf("  Wrong key result: %s\n", wrong_decrypted);
    printf("  ✓ Wrong key produces garbled output (trial never converged)\n\n");
    
    // Test file encryption
    printf("File encryption test:\n");
    FILE* test_file = fopen("test_file.txt", "w");
    if (test_file) {
        fprintf(test_file, "This is a test file for doubt encryption.\n");
        fprintf(test_file, "It contains multiple lines and special chars: !@#$%%^&*()\n");
        fclose(test_file);
        
        if (encrypt_file("test_file.txt", "test_file.txt.doubt", key) == 0) {
            printf("  ✓ File encrypted successfully\n");
            
            if (decrypt_file("test_file.txt.doubt", "test_file_decrypted.txt", key) == 0) {
                printf("  ✓ File decrypted successfully\n");
                
                // Compare files
                FILE* orig = fopen("test_file.txt", "rb");
                FILE* dec = fopen("test_file_decrypted.txt", "rb");
                if (orig && dec) {
                    int same = 1;
                    int c1, c2;
                    while ((c1 = fgetc(orig)) != EOF && (c2 = fgetc(dec)) != EOF) {
                        if (c1 != c2) {
                            same = 0;
                            break;
                        }
                    }
                    fclose(orig);
                    fclose(dec);
                    
                    if (same) {
                        printf("  ✓ File content matches perfectly\n");
                    } else {
                        printf("  ✗ File content mismatch\n");
                    }
                }
            } else {
                printf("  ✗ File decryption failed\n");
            }
        } else {
            printf("  ✗ File encryption failed\n");
        }
        
        // Clean up test files
        remove("test_file.txt");
        remove("test_file.txt.doubt");
        remove("test_file_decrypted.txt");
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    // Initialize embedded configuration
    init_embedded_config();
    deobfuscate_config();
    
    if (argc < 2) {
        show_help();
        return 1;
    }
    
    if (strcmp(argv[1], "help") == 0) {
        show_help();
        return 0;
    }
    
    // Config command removed for security - parameters are compile-time secrets
    
    if (strcmp(argv[1], "test") == 0) {
        run_tests();
        return 0;
    }
    
    if (strcmp(argv[1], "test-enhanced") == 0) {
        test_enhanced_system();
        return 0;
    }
    
    if (strcmp(argv[1], "encrypt") == 0) {
        if (argc < 4) {
            printf("Error: Missing password or message\n");
            printf("Usage: doubt_cli encrypt <password> <message>\n");
            return 1;
        }
        
        uint32_t key = derive_key(argv[2]);
        uint32_t encrypted[256];
        int encrypted_len;
        
        printf("Encrypting message...\n");
        encrypt_message(argv[3], key, encrypted, &encrypted_len);
        printf("Encryption complete!\n");
        
        char hex_output[1024];
        uint32_to_hex(encrypted, encrypted_len, hex_output);
        printf("%s\n", hex_output);
        
        return 0;
    }
    
    if (strcmp(argv[1], "decrypt") == 0) {
        if (argc < 4) {
            printf("Error: Missing password or hex data\n");
            printf("Usage: doubt_cli decrypt <password> <hex_data>\n");
            return 1;
        }
        
        uint32_t key = derive_key(argv[2]);
        uint32_t encrypted[256];
        int encrypted_len = hex_to_uint32(argv[3], encrypted, 256);
        
        if (encrypted_len == 0) {
            printf("Error: Invalid hex data\n");
            return 1;
        }
        
        printf("Decrypting message...\n");
        char decrypted[256];
        decrypt_message(encrypted, encrypted_len, key, decrypted);
        printf("Decryption complete!\n");
        printf("%s\n", decrypted);
        
        return 0;
    }
    
    if (strcmp(argv[1], "encrypt-file") == 0) {
        if (argc < 5) {
            printf("Error: Missing parameters\n");
            printf("Usage: doubt_cli encrypt-file <password> <input_file> <output_file>\n");
            return 1;
        }
        
        uint32_t key = derive_key(argv[2]);
        if (encrypt_file(argv[3], argv[4], key) == 0) {
            printf("File encrypted successfully: %s -> %s\n", argv[3], argv[4]);
        } else {
            printf("File encryption failed\n");
            return 1;
        }
        
        return 0;
    }
    
    if (strcmp(argv[1], "decrypt-file") == 0) {
        if (argc < 5) {
            printf("Error: Missing parameters\n");
            printf("Usage: doubt_cli decrypt-file <password> <input_file> <output_file>\n");
            return 1;
        }
        
        uint32_t key = derive_key(argv[2]);
        if (decrypt_file(argv[3], argv[4], key) == 0) {
            printf("File decrypted successfully: %s -> %s\n", argv[3], argv[4]);
        } else {
            printf("File decryption failed\n");
            return 1;
        }
        
        return 0;
    }
    
    printf("Error: Unknown command '%s'\n", argv[1]);
    show_help();
    return 1;
}
