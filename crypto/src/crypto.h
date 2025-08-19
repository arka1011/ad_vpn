#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t  key[32];     // traffic key (ChaCha20-Poly1305 key)
    uint8_t  salt[16];    // per-session salt (random)
    uint64_t send_seq;    // monotonic counter for nonces
    uint64_t recv_seq;    // receiver-side anti-replay/nonce sync baseline
} crypto_ctx_t;

/**
 * Fill buf[len] with cryptographically secure random bytes.
 * Returns 0 on success, -1 on failure.
 */
int crypto_random(void *buf, size_t len);

/**
 * AEAD encrypt (ChaCha20-Poly1305).
 * - Nonce = 12 bytes = salt[0..3] || be64(seq)
 * - AAD is authenticated but not encrypted.
 * - Output: ct = ciphertext || 16-byte tag    (ct_len = pt_len + 16)
 */
int crypto_aead_encrypt(const crypto_ctx_t *ctx,
                        uint64_t seq,
                        const uint8_t *pt, size_t pt_len,
                        const uint8_t *aad, size_t aad_len,
                        uint8_t *ct, size_t *ct_len);

/**
 * AEAD decrypt (ChaCha20-Poly1305).
 * - Expects ct = ciphertext || tag (last 16 bytes).
 * - Verifies tag; on success writes plaintext and sets pt_len.
 */
int crypto_aead_decrypt(const crypto_ctx_t *ctx,
                        uint64_t seq,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t *aad, size_t aad_len,
                        uint8_t *pt, size_t *pt_len);

/**
 * HKDF-Expand-Label (TLS 1.3 style, but with "vpn " prefix):
 * info = struct {
 *   uint16 length = out_len
 *   opaque label<7..255> = "vpn " + label
 *   opaque context<0..255> = info
 * }
 * out = HKDF-Expand(secret, info, out_len) using SHA-256.
 */
int crypto_hkdf_expand_label(const uint8_t *secret, size_t secret_len,
                             const char *label,
                             const uint8_t *info, size_t info_len,
                             uint8_t *out, size_t out_len);

/** X25519 key generation: fills pub[32], priv[32]. */
int crypto_x25519_keypair(uint8_t pub[32], uint8_t priv[32]);

/** X25519 shared secret: out[32] = X25519(priv, peer_pub). */
int crypto_x25519_shared(uint8_t out[32],
                         const uint8_t priv[32],
                         const uint8_t peer_pub[32]);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_H */
