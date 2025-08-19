#define _GNU_SOURCE
#include "crypto.h"

#include <string.h>
#include <errno.h>

#if defined(__linux__)
#include <sys/random.h>   // getrandom
#endif

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* ---------- Helpers ---------- */

static void be64(uint8_t out[8], uint64_t x) {
    out[0] = (uint8_t)(x >> 56);
    out[1] = (uint8_t)(x >> 48);
    out[2] = (uint8_t)(x >> 40);
    out[3] = (uint8_t)(x >> 32);
    out[4] = (uint8_t)(x >> 24);
    out[5] = (uint8_t)(x >> 16);
    out[6] = (uint8_t)(x >> 8);
    out[7] = (uint8_t)(x);
}

static void make_nonce(uint8_t nonce12[12], const crypto_ctx_t *ctx, uint64_t seq) {
    // 12-byte nonce: salt[0..3] || be64(seq)
    memcpy(nonce12, ctx->salt, 4);
    be64(nonce12 + 4, seq);
}

/* Cleanse sensitive data */
static void secure_bzero(void *p, size_t n) {
#if defined(OPENSSL_cleanse)
    OPENSSL_cleanse(p, n);
#else
    volatile uint8_t *vp = (volatile uint8_t*)p;
    while (n--) *vp++ = 0;
#endif
}

/* ---------- RNG ---------- */

int crypto_random(void *buf, size_t len) {
    if (len == 0) return 0;

#if defined(__linux__)
    ssize_t got = 0;
    uint8_t *p = (uint8_t*)buf;
    while ((size_t)got < len) {
        ssize_t n = getrandom(p + got, len - (size_t)got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        got += n;
    }
    if ((size_t)got == len) return 0;  // success
    // fall through to OpenSSL RAND_bytes as a fallback
#endif

    if (RAND_bytes((unsigned char*)buf, (int)len) == 1) return 0;
    return -1;
}

/* ---------- AEAD: ChaCha20-Poly1305 ---------- */

int crypto_aead_encrypt(const crypto_ctx_t *ctx,
                        uint64_t seq,
                        const uint8_t *pt, size_t pt_len,
                        const uint8_t *aad, size_t aad_len,
                        uint8_t *ct, size_t *ct_len) {
    if (!ctx || !pt || !ct || !ct_len) return -1;

    int ok = -1;
    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if (!cctx) return -1;

    uint8_t nonce[12];
    make_nonce(nonce, ctx, seq);

    int outl = 0, tmplen = 0;
    uint8_t seq_bytes[8];
    be64(seq_bytes, seq);

    if (EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_IVLEN, (int)sizeof(nonce), NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(cctx, NULL, NULL, ctx->key, nonce) != 1) goto done;

    // Bind the sequence number into AAD first (prevents reordering/replay)
    if (EVP_EncryptUpdate(cctx, NULL, &outl, seq_bytes, (int)sizeof(seq_bytes)) != 1) goto done;

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(cctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;
    }

    if (pt_len > 0) {
        if (EVP_EncryptUpdate(cctx, ct, &outl, pt, (int)pt_len) != 1) goto done;
    } else {
        outl = 0;
    }

    // Finalize (no extra bytes for stream ciphers, but required to compute tag)
    if (EVP_EncryptFinal_ex(cctx, ct + outl, &tmplen) != 1) goto done;
    outl += tmplen;

    // Get 16-byte tag and append to ciphertext
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, 16, ct + outl) != 1) goto done;
    outl += 16;

    *ct_len = (size_t)outl;
    ok = 0;

done:
    secure_bzero(seq_bytes, sizeof(seq_bytes));
    EVP_CIPHER_CTX_free(cctx);
    secure_bzero(nonce, sizeof(nonce));
    return ok;
}

int crypto_aead_decrypt(const crypto_ctx_t *ctx,
                        uint64_t seq,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t *aad, size_t aad_len,
                        uint8_t *pt, size_t *pt_len) {
    if (!ctx || !ct || !pt || !pt_len) return -1;
    if (ct_len < 16) return -1; // must have at least tag

    int ok = -1;
    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if (!cctx) return -1;

    uint8_t nonce[12];
    make_nonce(nonce, ctx, seq);

    // Split tag
    size_t data_len = ct_len - 16;
    const uint8_t *tag = ct + data_len;

    int outl = 0, tmplen = 0;
    uint8_t seq_bytes[8];
    be64(seq_bytes, seq);

    if (EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_IVLEN, (int)sizeof(nonce), NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(cctx, NULL, NULL, ctx->key, nonce) != 1) goto done;

    // AAD: sequence number first
    if (EVP_DecryptUpdate(cctx, NULL, &outl, seq_bytes, (int)sizeof(seq_bytes)) != 1) goto done;

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(cctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;
    }

    if (data_len > 0) {
        if (EVP_DecryptUpdate(cctx, pt, &outl, ct, (int)data_len) != 1) goto done;
    } else {
        outl = 0;
    }

    // Set expected tag before Final
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag) != 1) goto done;

    // Finalize (verifies tag)
    if (EVP_DecryptFinal_ex(cctx, pt + outl, &tmplen) != 1) goto done;
    outl += tmplen;

    *pt_len = (size_t)outl;
    ok = 0;

done:
    secure_bzero(seq_bytes, sizeof(seq_bytes));
    EVP_CIPHER_CTX_free(cctx);
    secure_bzero(nonce, sizeof(nonce));
    return ok;
}

/* ---------- X25519 Key Exchange ---------- */

int crypto_x25519_keypair(uint8_t pub[32], uint8_t priv[32]) {
    if (!pub || !priv) return -1;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    if (!pkey) return -1;

    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_free(pkey);
    return 0;
}

int crypto_x25519_shared(uint8_t out[32],
                         const uint8_t priv[32],
                         const uint8_t peer_pub[32]) {
    if (!out || !priv || !peer_pub) return -1;

    EVP_PKEY *priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    if (!priv_key) return -1;

    EVP_PKEY *pub_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (!pub_key) {
        EVP_PKEY_free(priv_key);
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        return -1;
    }

    if (EVP_PKEY_derive_set_peer(ctx, pub_key) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        return -1;
    }

    size_t shared_len = 32;
    if (EVP_PKEY_derive(ctx, out, &shared_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(pub_key);
    return 0;
}

/* ---------- HKDF Key Derivation ---------- */

int crypto_hkdf_expand_label(const uint8_t *secret, size_t secret_len,
                             const char *label,
                             const uint8_t *info, size_t info_len,
                             uint8_t *out, size_t out_len) {
    if (!secret || !label || !info || !out) return -1;

    // HKDF-Expand(Secret, Label, L) = HKDF-Expand(Secret, HkdfLabel, L)
    // where HkdfLabel = Label || " " || Hash(context)
    
    const EVP_MD *md = EVP_sha256();
    if (!md) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, (const unsigned char*)"", 0) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, secret_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // Create info: "vpn " + label + info
    size_t label_len = strlen(label);
    size_t total_info_len = 4 + label_len + info_len; // "vpn " + label + info
    uint8_t *total_info = malloc(total_info_len);
    if (!total_info) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    memcpy(total_info, "vpn ", 4);
    memcpy(total_info + 4, label, label_len);
    memcpy(total_info + 4 + label_len, info, info_len);

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, total_info, total_info_len) != 1) {
        free(total_info);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_derive(ctx, out, &out_len) != 1) {
        free(total_info);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    free(total_info);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}
