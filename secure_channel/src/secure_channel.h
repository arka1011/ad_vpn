#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========== Protocol constants ========== */

#define SC_PROTO_VER                 1
#define SC_MAX_RECORD_PLAINTEXT      1500   /* <= MTU-sized payload; adjust per link */
#define SC_TAG_LEN                   16     /* AEAD tag size (GCM/Poly1305) */
#define SC_NONCE_LEN                 12     /* AEAD nonce length (GCM/ChaCha20-Poly1305) */
#define SC_X25519_KEY_LEN            32
#define SC_HELLO_NONCE_LEN           16
#define SC_SEQ_LEN                   8      /* wire: 64-bit sequence */
#define SC_TYPE_DATA                 0x17   /* mirrors TLS content type values */
#define SC_TYPE_CONTROL              0x15

/* Error codes (negative for errors, >=0 for sizes/OK) */
#define SC_OK                        0
#define SC_ERR_IO                   -1
#define SC_ERR_PROTO                -2
#define SC_ERR_AUTH                 -3
#define SC_ERR_CRYPTO               -4
#define SC_ERR_REPLAY               -5
#define SC_ERR_STATE                -6
#define SC_ERR_PARAM                -7

/* Auth modes */
typedef enum { AUTH_PSK=1, AUTH_TOKEN=2, AUTH_MUTUALCERT=3 } auth_mode_t;

/* Control message types (within Type=control frames) */
typedef enum {
    SC_CTL_CLIENT_HELLO = 1,
    SC_CTL_SERVER_HELLO = 2,
    SC_CTL_FINISH       = 3,
    SC_CTL_FINISH_ACK   = 4
} sc_ctl_type_t;

/* AEAD cipher choice (compile-time or runtime switch) */
typedef enum { SC_CIPHER_CHACHA20_POLY1305 = 1, SC_CIPHER_AES_256_GCM = 2 } sc_cipher_t;

/* Forward decl for crypto context */
typedef struct crypto_ctx_s {
    sc_cipher_t cipher;
    uint8_t key[32];                 /* 256-bit key */
    uint8_t iv_base[SC_NONCE_LEN];   /* per-direction static IV/salt */
    uint64_t send_seq;               /* next seq to use for sender */
    uint64_t recv_highest;           /* highest authenticated seq seen */
    uint64_t recv_window;            /* sliding 64-bit bitmap for replay */
} crypto_ctx_t;

/* Public state for one secure channel (client or server) */
typedef struct {
    int sock_fd;

    /* Handshake artifacts */
    uint8_t c_pub[SC_X25519_KEY_LEN], c_priv[SC_X25519_KEY_LEN];
    uint8_t s_pub[SC_X25519_KEY_LEN];
    uint8_t shared[SC_X25519_KEY_LEN];
    uint8_t client_nonce[SC_HELLO_NONCE_LEN], server_nonce[SC_HELLO_NONCE_LEN];

    /* Derived keys (split per direction) */
    crypto_ctx_t tx;  /* keys + seq for local->peer */
    crypto_ctx_t rx;  /* keys + replay window for peer->local */

    auth_mode_t auth_mode;
    char        psk_hex[65]; /* if PSK (hex-encoded 32-byte key) */
    char        token[128];  /* if token (JWT, opaque, etc.) */

    int         is_established;
    sc_cipher_t cipher;      /* negotiated/selected */
} secure_chan_t;

/* ========== Callbacks (optional; set to NULL to use defaults) ========== */

/* RNG: fill buf with cryptographically secure bytes, return 0 on success */
typedef int (*sc_rng_fn)(void *user, uint8_t *buf, size_t len);

/* Time (for rekey policy): return Unix seconds */
typedef uint64_t (*sc_time_fn)(void *user);

/* Token verifier: return 0 if token is valid and issued by expected_issuer */
typedef int (*sc_token_verify_fn)(void *user, const char *token, const char *expected_issuer);

/* Certificate verifier (mutual cert): return 0 if peer passed verification */
typedef int (*sc_cert_verify_fn)(void *user /*, add cert params as needed */);

/* App-supplied hooks (optional) */
typedef struct {
    sc_rng_fn           rng;
    sc_time_fn          now;
    sc_token_verify_fn  token_verify;
    sc_cert_verify_fn   cert_verify;
    void               *user; /* passed to all callbacks */
} sc_hooks_t;

/* ========== API ========== */

/* Initialize/zero a channel (no socket ops) */
void sc_init(secure_chan_t *sc, sc_cipher_t cipher, const sc_hooks_t *hooks);

/* CLIENT: start handshake (generate X25519 + nonce, send CLIENT_HELLO) */
int sc_client_begin(secure_chan_t *sc, int sock_fd, auth_mode_t mode, const char *psk_or_token);

/* CLIENT: finish handshake (process SERVER_HELLO, derive keys, FINISH/ACK) */
int sc_client_finish(secure_chan_t *sc);

/* SERVER: accept and complete handshake (read CLIENT_HELLO, auth, reply) */
int sc_server_accept(secure_chan_t *sc, int sock_fd, auth_mode_t expected_mode, const char *expected_psk_or_issuer);

/* Common data path */
ssize_t sc_send_data(secure_chan_t *sc, const uint8_t *buf, size_t len);
ssize_t sc_recv_data(secure_chan_t *sc, uint8_t *out, size_t maxlen);

/* Close channel (zero keys, close fd not owned? You decide policy) */
void sc_close(secure_chan_t *sc);

/* Rekey policy hook (call from send/recv or app loop) */
int sc_rekey_if_needed(secure_chan_t *sc, uint64_t bytes_sent, uint64_t secs);

/* Helpers to convert hex PSK into bytes (returns len or <0) */
int sc_hex2bin(const char *hex, uint8_t *out, size_t out_len);

/* Optional: set custom hooks post-init */
void sc_set_hooks(secure_chan_t *sc, const sc_hooks_t *hooks);

/* ========== Record framing (wire) ========== */
/*
   [ Type(1) | Seq(8) | Len(2) | Ciphertext(Len) | Tag(16) ]
   AAD = Type || Seq || Len      (all big-endian on wire)
   Seq = per-direction counter (monotonic, starting at 0)
   Nonce = iv_base (12B) XOR encode64(Seq) (right-aligned)
*/

#ifdef __cplusplus
}
#endif
#endif /* SECURE_CHANNEL_H */
