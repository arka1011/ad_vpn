# Crypto Module

A cryptographic utilities module providing secure random number generation, AEAD encryption/decryption, key derivation, and X25519 key exchange using OpenSSL.

## Features

- **Secure Random Generation**: Cryptographically secure random numbers
- **AEAD Encryption**: ChaCha20-Poly1305 and AES-256-GCM encryption
- **Key Derivation**: HKDF for secure key derivation
- **X25519 Key Exchange**: Elliptic curve key exchange for perfect forward secrecy
- **Anti-replay Protection**: Sequence number-based replay protection

## Directory Structure

```
crypto/
├── src/                    # Source code
│   ├── crypto.c           # Main crypto implementation
│   └── crypto.h           # Public header file
├── tests/                 # Test suite
│   ├── test_crypto.c      # Unit tests
│   └── Makefile          # Test build configuration
├── build/                 # Local build artifacts
│   ├── lib/              # Libraries
│   ├── bin/              # Executables
│   └── include/          # Headers
├── Makefile              # Build configuration
├── README.md             # This file
└── .gitignore           # Git ignore rules
```

## Building

### Build Everything
```bash
make all
```

### Build Libraries Only
```bash
make lib
```

### Run Tests
```bash
make -C tests test
```

### Clean Build Artifacts
```bash
make clean
```

## Usage

### Basic Usage
```c
#include "src/crypto.h"

int main() {
    // Generate random bytes
    uint8_t random[32];
    if (crypto_random(random, sizeof(random)) < 0) {
        fprintf(stderr, "Failed to generate random bytes\n");
        return 1;
    }
    
    // Generate X25519 keypair
    uint8_t private_key[32], public_key[32];
    if (crypto_x25519_keypair(private_key, public_key) < 0) {
        fprintf(stderr, "Failed to generate keypair\n");
        return 1;
    }
    
    // Encrypt data
    uint8_t plaintext[] = "Hello, World!";
    uint8_t ciphertext[256];
    uint8_t tag[16];
    uint64_t seq_num = 1;
    
    size_t ciphertext_len;
    if (crypto_aead_encrypt(ciphertext, &ciphertext_len, tag,
                           plaintext, strlen((char*)plaintext),
                           NULL, 0, seq_num) < 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    
    return 0;
}
```

### Key Exchange
```c
uint8_t alice_private[32], alice_public[32];
uint8_t bob_private[32], bob_public[32];
uint8_t alice_shared[32], bob_shared[32];

// Generate keypairs
crypto_x25519_keypair(alice_private, alice_public);
crypto_x25519_keypair(bob_private, bob_public);

// Compute shared secrets
crypto_x25519_shared(alice_shared, alice_private, bob_public);
crypto_x25519_shared(bob_shared, bob_private, alice_public);

// alice_shared and bob_shared should be identical
```

### Key Derivation
```c
uint8_t key_material[32];
uint8_t derived_key[32];

// Derive key using HKDF
if (crypto_hkdf_expand_label(derived_key, sizeof(derived_key),
                            key_material, sizeof(key_material),
                            "key", 3, NULL, 0) < 0) {
    fprintf(stderr, "Key derivation failed\n");
    return 1;
}
```

## API Reference

### Random Number Generation
- `crypto_random(void *out, size_t len)` - Generate secure random bytes

### X25519 Key Exchange
- `crypto_x25519_keypair(uint8_t *private_key, uint8_t *public_key)` - Generate keypair
- `crypto_x25519_shared(uint8_t *shared, const uint8_t *private_key, const uint8_t *public_key)` - Compute shared secret

### Key Derivation
- `crypto_hkdf_expand_label(uint8_t *out, size_t out_len, const uint8_t *key, size_t key_len, const char *label, size_t label_len, const uint8_t *context, size_t context_len)` - HKDF key derivation

### AEAD Encryption
- `crypto_aead_encrypt(uint8_t *ciphertext, size_t *ciphertext_len, uint8_t *tag, const uint8_t *plaintext, size_t plaintext_len, const uint8_t *aad, size_t aad_len, uint64_t seq_num)` - Encrypt with AEAD
- `crypto_aead_decrypt(uint8_t *plaintext, size_t *plaintext_len, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint64_t seq_num)` - Decrypt with AEAD

## Dependencies

- **OpenSSL**: For cryptographic operations
- **Standard C library**: For memory and string operations

## Requirements

- OpenSSL development headers
- OpenSSL runtime library
- C99 compatible compiler

## Installation

### System-wide Installation
```bash
sudo make install
```

### Uninstall
```bash
sudo make uninstall
```

## Testing

Run the test suite to verify functionality:
```bash
make -C tests test
```

## Security Considerations

- Uses cryptographically secure random number generation
- Implements perfect forward secrecy with X25519
- Provides anti-replay protection with sequence numbers
- Uses AEAD encryption for authenticated encryption

## License

This module is part of the AD VPN project and follows the same license terms.
