/* secure_channel.c
 *
 * Implementation of secure_channel using OpenSSL and the provided logger.
 *
 * Build (example):
 *   gcc -O2 -Wall secure_channel.c -o secure_channel -lssl -lcrypto -pthread
 *
 * Notes:
 * - Requires OpenSSL >= 1.1.1 (for EVP_chacha20_poly1305 / X25519 APIs).
 * - The logger functions are called (logger.h). Provide logger implementation separately.
 */

#include "secure_channel.h"
#include "../../logger/src/logger.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

/* === Forward declarations (crypto helpers implemented below) === */
static int sc_x25519_keypair(uint8_t pub[32], uint8_t priv[32]);
static int sc_x25519_shared(uint8_t out[32], const uint8_t priv[32], const uint8_t peer_pub[32]);
static int sc_hkdf_expand_openssl(uint8_t *out, size_t out_len,
                                  const uint8_t *salt, size_t salt_len,
                                  const uint8_t *ikm, size_t ikm_len,
                                  const uint8_t *info, size_t info_len);
static int sc_aead_encrypt(sc_cipher_t c,
                           const uint8_t key[32], const uint8_t nonce[SC_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct, uint8_t tag[SC_TAG_LEN]);
static int sc_aead_decrypt(sc_cipher_t c,
                           const uint8_t key[32], const uint8_t nonce[SC_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[SC_TAG_LEN],
                           uint8_t *pt);

/* Keep hooks global as in skeleton */
static sc_hooks_t g_hooks = {0};

/* utility functions (same as skeleton but fully implemented) */

static void u64_to_be(uint64_t v, uint8_t out[8]) {
    out[0]=(uint8_t)(v>>56); out[1]=(uint8_t)(v>>48); out[2]=(uint8_t)(v>>40); out[3]=(uint8_t)(v>>32);
    out[4]=(uint8_t)(v>>24); out[5]=(uint8_t)(v>>16); out[6]=(uint8_t)(v>>8);  out[7]=(uint8_t)(v);
}
static void u16_to_be(uint16_t v, uint8_t out[2]) { out[0]=(uint8_t)(v>>8); out[1]=(uint8_t)v; }

static int sc_default_rng(void *u, uint8_t *buf, size_t len) {
    (void)u;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, buf + got, len - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}
static uint64_t sc_default_time(void *u) {
    (void)u;
    return (uint64_t)time(NULL);
}
static int sc_get_rng(const secure_chan_t *sc, uint8_t *buf, size_t len) {
    (void)sc;
    sc_rng_fn rng = g_hooks.rng ? g_hooks.rng : sc_default_rng;
    return rng(g_hooks.user, buf, len);
}
static uint64_t sc_now(void) {
    sc_time_fn now = g_hooks.now ? g_hooks.now : sc_default_time;
    return now(g_hooks.user);
}

/* XOR right-aligned seq into 12B IV base */
static void sc_build_nonce(uint8_t out[SC_NONCE_LEN],
                           const uint8_t iv_base[SC_NONCE_LEN],
                           uint64_t seq) {
    memcpy(out, iv_base, SC_NONCE_LEN);
    for (int i = 0; i < 8; ++i) {
        out[SC_NONCE_LEN - 1 - i] ^= (uint8_t)(seq >> (8*i));
    }
}

/* Sliding window replay protection (64-bit) */
static int sc_replay_check_and_set(crypto_ctx_t *rx, uint64_t seq) {
    if (rx->recv_highest == UINT64_MAX) {
        /* uninitialized: accept first as highest */
        rx->recv_highest = seq;
        rx->recv_window = 1ULL;
        return 0;
    }
    if (seq > rx->recv_highest) {
        uint64_t shift = seq - rx->recv_highest;
        if (shift >= 64) {
            rx->recv_window = 0ULL;
        } else {
            rx->recv_window <<= shift;
        }
        rx->recv_window |= 1ULL;
        rx->recv_highest = seq;
        return 0;
    } else {
        uint64_t delta = rx->recv_highest - seq;
        if (delta >= 64) return SC_ERR_REPLAY;
        uint64_t mask = 1ULL << delta;
        if (rx->recv_window & mask) return SC_ERR_REPLAY;
        rx->recv_window |= mask;
        return 0;
    }
}

/* send_all / recv_n (same as skeleton) */
static ssize_t send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t*)buf; size_t n = len;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("send_all write error: %s", strerror(errno));
            return SC_ERR_IO;
        }
        p += w; n -= w;
    }
    return (ssize_t)len;
}
static ssize_t recv_n(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t*)buf; size_t n = len;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r == 0) {
            LOG_WARN("recv_n EOF");
            return SC_ERR_IO;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("recv_n read error: %s", strerror(errno));
            return SC_ERR_IO;
        }
        p += r; n -= r;
    }
    return (ssize_t)len;
}

/* zeroize */
static void sc_memzero(void *p, size_t n) { volatile uint8_t *v = (volatile uint8_t*)p; while (n--) *v++ = 0; }

/* --- HKDF / key derivation helper --- */
/* We will directly derive the needed bytes using HKDF(sha256) with shared as IKM and salt=client||server nonces.
 * total output needed = 32+12 + 32+12 = 88 bytes
 */
static int sc_derive_keys(secure_chan_t *sc) {
    uint8_t salt[SC_HELLO_NONCE_LEN * 2];
    memcpy(salt, sc->client_nonce, SC_HELLO_NONCE_LEN);
    memcpy(salt + SC_HELLO_NONCE_LEN, sc->server_nonce, SC_HELLO_NONCE_LEN);

    const size_t need = 32 + SC_NONCE_LEN + 32 + SC_NONCE_LEN; /* 88 */
    uint8_t out[88];

    if (sc_hkdf_expand_openssl(out, need, salt, sizeof(salt), sc->shared, SC_X25519_KEY_LEN,
                               (const uint8_t*)"sc v1", 5) != 0) {
        LOG_ERROR("HKDF expand failed");
        return SC_ERR_CRYPTO;
    }

    uint8_t *k1 = out + 0;
    uint8_t *iv1 = out + 32;
    uint8_t *k2 = out + 32 + SC_NONCE_LEN;
    uint8_t *iv2 = out + 64 + SC_NONCE_LEN; /* exactly 88 bytes */

    /* Determine role: if c_priv is non-zero we were the client at key generation time */
    int is_client = 0;
    for (size_t i = 0; i < SC_X25519_KEY_LEN; ++i) {
        if (sc->c_priv[i] != 0) { is_client = 1; break; }
    }

    sc->tx.cipher = sc->cipher;
    sc->rx.cipher = sc->cipher;

    if (is_client) {
        memcpy(sc->tx.key, k1, 32); memcpy(sc->tx.iv_base, iv1, SC_NONCE_LEN);
        memcpy(sc->rx.key, k2, 32); memcpy(sc->rx.iv_base, iv2, SC_NONCE_LEN);
    } else {
        memcpy(sc->rx.key, k1, 32); memcpy(sc->rx.iv_base, iv1, SC_NONCE_LEN);
        memcpy(sc->tx.key, k2, 32); memcpy(sc->tx.iv_base, iv2, SC_NONCE_LEN);
    }

    sc->tx.send_seq = 0;
    sc->rx.recv_highest = UINT64_MAX; /* marks uninitialized sentinel used in replay function */
    sc->rx.recv_window = 0;

    sc_memzero(out, sizeof(out));
    sc_memzero(salt, sizeof(salt));
    return SC_OK;
}

/* ===== API implementations (based on skeleton) ===== */

void sc_init(secure_chan_t *sc, sc_cipher_t cipher, const sc_hooks_t *hooks) {
    if (!sc) return;
    memset(sc, 0, sizeof(*sc));
    sc->cipher = cipher ? cipher : SC_CIPHER_CHACHA20_POLY1305;
    if (hooks) g_hooks = *hooks;
    /* Initialize OpenSSL error strings for easier debugging */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

void sc_set_hooks(secure_chan_t *sc, const sc_hooks_t *hooks) {
    (void)sc;
    if (hooks) g_hooks = *hooks;
}

/* control record helpers (same semantics as skeleton) */
static int send_control_record(secure_chan_t *sc, sc_ctl_type_t t, const uint8_t *payload, uint16_t plen) {
    if (!sc) return SC_ERR_PARAM;
    uint8_t header_fixed[1 + SC_SEQ_LEN + 2];
    header_fixed[0] = SC_TYPE_CONTROL;
    memset(header_fixed + 1, 0, SC_SEQ_LEN); /* seq=0 for pre-handshake control */
    header_fixed[1 + SC_SEQ_LEN + 0] = (uint8_t)((4 + plen) >> 8);
    header_fixed[1 + SC_SEQ_LEN + 1] = (uint8_t)((4 + plen) & 0xff);

    /* Build inner TLV */
    uint8_t tlv[4 + 65535];
    if (4 + plen > sizeof(tlv)) return SC_ERR_PARAM;
    tlv[0] = (uint8_t)t;
    tlv[1] = (uint8_t)SC_PROTO_VER;
    tlv[2] = (uint8_t)(plen >> 8);
    tlv[3] = (uint8_t)(plen & 0xff);
    memcpy(tlv + 4, payload, plen);

    /* tag field set to zero pre-keys for simplicity */
    uint8_t zero_tag[SC_TAG_LEN];
    memset(zero_tag, 0, sizeof(zero_tag));

    /* send header_fixed || tlv || tag */
    if (send_all(sc->sock_fd, header_fixed, sizeof(header_fixed)) < 0) return SC_ERR_IO;
    if (send_all(sc->sock_fd, tlv, 4 + plen) < 0) return SC_ERR_IO;
    if (send_all(sc->sock_fd, zero_tag, sizeof(zero_tag)) < 0) return SC_ERR_IO;
    LOG_DEBUG("sent control record type=%d len=%u", (int)t, (unsigned)plen);
    return SC_OK;
}

static int recv_control_record(secure_chan_t *sc, sc_ctl_type_t *out_t, uint8_t *buf, uint16_t *inout_len) {
    if (!sc || !out_t || !buf || !inout_len) return SC_ERR_PARAM;
    uint8_t fixed[1 + SC_SEQ_LEN + 2];
    if (recv_n(sc->sock_fd, fixed, sizeof(fixed)) < 0) return SC_ERR_IO;
    if (fixed[0] != SC_TYPE_CONTROL) {
        LOG_ERROR("recv_control_record: unexpected type: %02x", fixed[0]);
        return SC_ERR_PROTO;
    }
    uint16_t len = ((uint16_t)fixed[1 + SC_SEQ_LEN] << 8) | fixed[1 + SC_SEQ_LEN + 1];
    if (len > *inout_len) {
        LOG_ERROR("recv_control_record: buffer too small (%u > %u)", len, *inout_len);
        return SC_ERR_PROTO;
    }
    if (recv_n(sc->sock_fd, buf, len) < 0) return SC_ERR_IO;
    uint8_t tag[SC_TAG_LEN];
    if (recv_n(sc->sock_fd, tag, sizeof(tag)) < 0) return SC_ERR_IO;

    if (len < 4) return SC_ERR_PROTO;
    *out_t = (sc_ctl_type_t)buf[0];
    uint8_t ver = buf[1];
    if (ver != SC_PROTO_VER) {
        LOG_ERROR("recv_control_record: proto mismatch %u vs %u", ver, SC_PROTO_VER);
        return SC_ERR_PROTO;
    }
    uint16_t p_len = ((uint16_t)buf[2] << 8) | buf[3];
    if (4 + p_len != len) return SC_ERR_PROTO;

    /* move payload to front */
    memmove(buf, buf+4, p_len);
    *inout_len = p_len;
    LOG_DEBUG("received control record type=%d payload_len=%u", (int)*out_t, p_len);
    return SC_OK;
}

/* CLIENT: sc_client_begin */
int sc_client_begin(secure_chan_t *sc, int sock_fd, auth_mode_t mode, const char *psk_or_token) {
    if (!sc || sock_fd < 0) return SC_ERR_PARAM;
    sc->sock_fd = sock_fd;
    sc->auth_mode = mode;

    /* Generate X25519 keypair and nonce */
    if (sc_x25519_keypair(sc->c_pub, sc->c_priv) != 0) {
        LOG_ERROR("sc_client_begin: x25519 keypair failed");
        return SC_ERR_CRYPTO;
    }
    if (sc_get_rng(sc, sc->client_nonce, SC_HELLO_NONCE_LEN) != 0) {
        LOG_ERROR("sc_client_begin: rng failed");
        return SC_ERR_CRYPTO;
    }

    if (mode == AUTH_PSK && psk_or_token) {
        size_t n = strnlen(psk_or_token, sizeof(sc->psk_hex)-1);
        memcpy(sc->psk_hex, psk_or_token, n); sc->psk_hex[n]=0;
    } else if (mode == AUTH_TOKEN && psk_or_token) {
        size_t n = strnlen(psk_or_token, sizeof(sc->token)-1);
        memcpy(sc->token, psk_or_token, n); sc->token[n]=0;
    }

    uint8_t payload[1 + SC_X25519_KEY_LEN + SC_HELLO_NONCE_LEN + 1 + 2 + 256];
    uint8_t *p = payload;
    *p++ = (uint8_t)SC_PROTO_VER;
    memcpy(p, sc->c_pub, SC_X25519_KEY_LEN); p += SC_X25519_KEY_LEN;
    memcpy(p, sc->client_nonce, SC_HELLO_NONCE_LEN); p += SC_HELLO_NONCE_LEN;
    *p++ = (uint8_t)mode;

    uint16_t auth_len = 0;
    if (mode == AUTH_PSK) auth_len = (uint16_t)strnlen(sc->psk_hex, sizeof(sc->psk_hex));
    else if (mode == AUTH_TOKEN) auth_len = (uint16_t)strnlen(sc->token, sizeof(sc->token));
    p[0] = (uint8_t)(auth_len >> 8); p[1] = (uint8_t)(auth_len & 0xff); p += 2;
    if (auth_len) {
        const char *ad = (mode == AUTH_PSK) ? sc->psk_hex : sc->token;
        memcpy(p, ad, auth_len); p += auth_len;
    }
    uint16_t plen = (uint16_t)(p - payload);

    int rc = send_control_record(sc, SC_CTL_CLIENT_HELLO, payload, plen);
    if (rc != SC_OK) {
        LOG_ERROR("sc_client_begin: send CLIENT_HELLO failed");
        return rc;
    }
    LOG_INFO("CLIENT_HELLO sent");
    return SC_OK;
}

/* CLIENT: sc_client_finish */
int sc_client_finish(secure_chan_t *sc) {
    if (!sc) return SC_ERR_PARAM;
    uint8_t buf[1 + 32 + 16 + 1 + 2 + 256];
    uint16_t blen = sizeof(buf);
    sc_ctl_type_t t;
    int rc = recv_control_record(sc, &t, buf, &blen);
    if (rc != SC_OK) return rc;
    if (t != SC_CTL_SERVER_HELLO) {
        LOG_ERROR("sc_client_finish: expected SERVER_HELLO");
        return SC_ERR_PROTO;
    }

    uint8_t *p = buf;
    uint8_t ver = *p++; (void)ver;
    memcpy(sc->s_pub, p, SC_X25519_KEY_LEN); p += SC_X25519_KEY_LEN;
    memcpy(sc->server_nonce, p, SC_HELLO_NONCE_LEN); p += SC_HELLO_NONCE_LEN;
    uint8_t auth_required = *p++; (void)auth_required;
    uint16_t params_len = ((uint16_t)p[0] << 8) | p[1]; p += 2;
    (void)params_len;

    /* Compute ECDH shared secret */
    if (sc_x25519_shared(sc->shared, sc->c_priv, sc->s_pub) != 0) {
        LOG_ERROR("sc_client_finish: x25519 shared failed");
        return SC_ERR_CRYPTO;
    }

    /* Derive keys */
    rc = sc_derive_keys(sc);
    if (rc != SC_OK) {
        LOG_ERROR("sc_client_finish: key derivation failed");
        return rc;
    }

    /* Send FINISH: create tag using AEAD with AAD = "finish" */
    uint8_t aad[] = { 'f','i','n','i','s','h' };
    uint8_t nonce[SC_NONCE_LEN];
    sc_build_nonce(nonce, sc->tx.iv_base, sc->tx.send_seq);
    uint8_t tag[SC_TAG_LEN];
    if (sc_aead_encrypt(sc->tx.cipher, sc->tx.key, nonce, aad, sizeof(aad),
                        NULL, 0, NULL, tag) != 0) {
        LOG_ERROR("sc_client_finish: AEAD encrypt FINISH failed");
        return SC_ERR_CRYPTO;
    }

    if (send_control_record(sc, SC_CTL_FINISH, tag, SC_TAG_LEN) != SC_OK) {
        LOG_ERROR("sc_client_finish: send FINISH failed");
        return SC_ERR_IO;
    }
    sc->tx.send_seq++;
    LOG_INFO("FINISH sent, waiting FINISH_ACK");

    /* Wait FINISH_ACK */
    blen = sizeof(buf);
    rc = recv_control_record(sc, &t, buf, &blen);
    if (rc != SC_OK) return rc;
    if (t != SC_CTL_FINISH_ACK || blen != SC_TAG_LEN) {
        LOG_ERROR("sc_client_finish: expected FINISH_ACK");
        return SC_ERR_PROTO;
    }

    uint8_t srv_tag[SC_TAG_LEN];
    memcpy(srv_tag, buf, SC_TAG_LEN);

    uint8_t srv_nonce[SC_NONCE_LEN];
    sc_build_nonce(srv_nonce, sc->rx.iv_base, 0);

    uint8_t aad2[] = { 'f','i','n','i','s','h','_','a','c' };
    uint8_t dummy;
    if (sc_aead_decrypt(sc->rx.cipher, sc->rx.key, srv_nonce, aad2, sizeof(aad2),
                        NULL, 0, srv_tag, &dummy) != 0) {
        LOG_ERROR("sc_client_finish: FINISH_ACK verification failed");
        return SC_ERR_CRYPTO;
    }

    sc->is_established = 1;
    sc_memzero(sc->c_priv, sizeof(sc->c_priv));
    LOG_INFO("Handshake complete: channel established");
    return SC_OK;
}

/* SERVER: sc_server_accept */
int sc_server_accept(secure_chan_t *sc, int sock_fd, auth_mode_t expected_mode, const char *expected_psk_or_issuer) {
    if (!sc || sock_fd < 0) return SC_ERR_PARAM;
    sc->sock_fd = sock_fd;

    uint8_t buf[1 + 32 + 16 + 1 + 2 + 512];
    uint16_t blen = sizeof(buf);
    sc_ctl_type_t t;
    int rc = recv_control_record(sc, &t, buf, &blen);
    if (rc != SC_OK) return rc;
    if (t != SC_CTL_CLIENT_HELLO) {
        LOG_ERROR("sc_server_accept: expected CLIENT_HELLO");
        return SC_ERR_PROTO;
    }

    uint8_t *p = buf;
    uint8_t ver = *p++;
    if (ver != SC_PROTO_VER) {
        LOG_ERROR("sc_server_accept: proto version mismatch");
        return SC_ERR_PROTO;
    }

    uint8_t client_pub[SC_X25519_KEY_LEN];
    memcpy(client_pub, p, SC_X25519_KEY_LEN); p += SC_X25519_KEY_LEN;
    memcpy(sc->c_pub, client_pub, SC_X25519_KEY_LEN);
    memcpy(sc->client_nonce, p, SC_HELLO_NONCE_LEN); p += SC_HELLO_NONCE_LEN;
    uint8_t auth_method = *p++;
    uint16_t auth_len = ((uint16_t)p[0] << 8) | p[1]; p += 2;
    const char *auth_data = (const char*)p; (void)auth_data;

    if ((auth_mode_t)auth_method != expected_mode) {
        LOG_ERROR("sc_server_accept: auth method mismatch (got %d expect %d)", auth_method, expected_mode);
        return SC_ERR_AUTH;
    }

    /* Simple auth checks */
    if (expected_mode == AUTH_PSK) {
        if (!expected_psk_or_issuer || auth_len != (int)strnlen(expected_psk_or_issuer, 64) ||
            memcmp(auth_data, expected_psk_or_issuer, auth_len) != 0) {
            LOG_ERROR("sc_server_accept: PSK mismatch");
            return SC_ERR_AUTH;
        }
    } else if (expected_mode == AUTH_TOKEN) {
        if (!g_hooks.token_verify) {
            LOG_ERROR("sc_server_accept: token_verify hook not set");
            return SC_ERR_AUTH;
        }
        if (g_hooks.token_verify(g_hooks.user, auth_data, expected_psk_or_issuer) != 0) {
            LOG_ERROR("sc_server_accept: token verify failed");
            return SC_ERR_AUTH;
        }
    } else if (expected_mode == AUTH_MUTUALCERT) {
        if (!g_hooks.cert_verify) {
            LOG_ERROR("sc_server_accept: cert_verify hook not set");
            return SC_ERR_AUTH;
        }
        if (g_hooks.cert_verify(g_hooks.user) != 0) {
            LOG_ERROR("sc_server_accept: cert verify failed");
            return SC_ERR_AUTH;
        }
    }

    /* Generate server keypair and nonce */
    uint8_t s_priv[SC_X25519_KEY_LEN];
    if (sc_x25519_keypair(sc->s_pub, s_priv) != 0) {
        LOG_ERROR("sc_server_accept: x25519 keypair failed");
        return SC_ERR_CRYPTO;
    }
    if (sc_get_rng(sc, sc->server_nonce, SC_HELLO_NONCE_LEN) != 0) {
        LOG_ERROR("sc_server_accept: rng failed");
        return SC_ERR_CRYPTO;
    }

    /* Compute shared = X25519(s_priv, client_pub) */
    if (sc_x25519_shared(sc->shared, s_priv, client_pub) != 0) {
        LOG_ERROR("sc_server_accept: x25519 shared failed");
        sc_memzero(s_priv, sizeof(s_priv));
        return SC_ERR_CRYPTO;
    }

    /* Mark role (server) by clearing c_priv so derive_keys flips appropriately */
    memset(sc->c_priv, 0, sizeof(sc->c_priv));

    rc = sc_derive_keys(sc);
    if (rc != SC_OK) {
        LOG_ERROR("sc_server_accept: derive keys failed");
        sc_memzero(s_priv, sizeof(s_priv));
        return rc;
    }

    /* Send SERVER_HELLO */
    uint8_t sh[1 + 32 + 16 + 1 + 2];
    uint8_t *q = sh;
    *q++ = (uint8_t)SC_PROTO_VER;
    memcpy(q, sc->s_pub, SC_X25519_KEY_LEN); q += SC_X25519_KEY_LEN;
    memcpy(q, sc->server_nonce, SC_HELLO_NONCE_LEN); q += SC_HELLO_NONCE_LEN;
    *q++ = 0; /* auth_required = 0 (we already authenticated) */
    uint16_t params_len = 0;
    q[0] = (uint8_t)(params_len >> 8); q[1] = (uint8_t)(params_len & 0xff); q += 2;

    if (send_control_record(sc, SC_CTL_SERVER_HELLO, sh, (uint16_t)(q - sh)) != SC_OK) {
        LOG_ERROR("sc_server_accept: send SERVER_HELLO failed");
        sc_memzero(s_priv, sizeof(s_priv));
        return SC_ERR_IO;
    }

    /* Expect FINISH */
    blen = sizeof(buf);
    rc = recv_control_record(sc, &t, buf, &blen);
    if (rc != SC_OK) {
        sc_memzero(s_priv, sizeof(s_priv));
        return rc;
    }
    if (t != SC_CTL_FINISH || blen != SC_TAG_LEN) {
        LOG_ERROR("sc_server_accept: expected FINISH");
        sc_memzero(s_priv, sizeof(s_priv));
        return SC_ERR_PROTO;
    }

    uint8_t cli_tag[SC_TAG_LEN];
    memcpy(cli_tag, buf, SC_TAG_LEN);

    uint8_t nonce[SC_NONCE_LEN];
    sc_build_nonce(nonce, sc->rx.iv_base, 0);
    uint8_t aad[] = { 'f','i','n','i','s','h' };
    uint8_t dummy;
    if (sc_aead_decrypt(sc->rx.cipher, sc->rx.key, nonce, aad, sizeof(aad),
                        NULL, 0, cli_tag, &dummy) != 0) {
        LOG_ERROR("sc_server_accept: FINISH verification failed");
        sc_memzero(s_priv, sizeof(s_priv));
        return SC_ERR_CRYPTO;
    }

    /* Send FINISH_ACK */
    uint8_t ack_tag[SC_TAG_LEN];
    uint8_t aad2[] = { 'f','i','n','i','s','h','_','a','c' };
    sc_build_nonce(nonce, sc->tx.iv_base, sc->tx.send_seq);
    if (sc_aead_encrypt(sc->tx.cipher, sc->tx.key, nonce, aad2, sizeof(aad2), NULL, 0, NULL, ack_tag) != 0) {
        LOG_ERROR("sc_server_accept: AEAD encrypt FINISH_ACK failed");
        sc_memzero(s_priv, sizeof(s_priv));
        return SC_ERR_CRYPTO;
    }
    if (send_control_record(sc, SC_CTL_FINISH_ACK, ack_tag, SC_TAG_LEN) != SC_OK) {
        LOG_ERROR("sc_server_accept: send FINISH_ACK failed");
        sc_memzero(s_priv, sizeof(s_priv));
        return SC_ERR_IO;
    }
    sc->tx.send_seq++;
    sc->is_established = 1;
    sc_memzero(s_priv, sizeof(s_priv));
    LOG_INFO("Handshake complete (server): channel established");
    return SC_OK;
}

/* sc_send_data */
ssize_t sc_send_data(secure_chan_t *sc, const uint8_t *buf, size_t len) {
    if (!sc || !sc->is_established) return SC_ERR_STATE;
    if (len > SC_MAX_RECORD_PLAINTEXT) return SC_ERR_PARAM;

    uint8_t header[1 + SC_SEQ_LEN + 2];
    header[0] = SC_TYPE_DATA;
    u64_to_be(sc->tx.send_seq, header + 1);
    u16_to_be((uint16_t)len, header + 1 + SC_SEQ_LEN);

    uint8_t nonce[SC_NONCE_LEN];
    sc_build_nonce(nonce, sc->tx.iv_base, sc->tx.send_seq);

    /* ciphertext buffer */
    uint8_t ct[SC_MAX_RECORD_PLAINTEXT];
    uint8_t tag[SC_TAG_LEN];

    if (sc_aead_encrypt(sc->tx.cipher, sc->tx.key, nonce, header, sizeof(header),
                        buf, len, ct, tag) != 0) {
        LOG_ERROR("sc_send_data: AEAD encrypt failed");
        return SC_ERR_CRYPTO;
    }

    if (send_all(sc->sock_fd, header, sizeof(header)) < 0) return SC_ERR_IO;
    if (send_all(sc->sock_fd, ct, len) < 0) return SC_ERR_IO;
    if (send_all(sc->sock_fd, tag, sizeof(tag)) < 0) return SC_ERR_IO;

    sc->tx.send_seq++;
    return (ssize_t)len;
}

/* sc_recv_data */
ssize_t sc_recv_data(secure_chan_t *sc, uint8_t *out, size_t maxlen) {
    if (!sc || !sc->is_established) return SC_ERR_STATE;

    uint8_t header[1 + SC_SEQ_LEN + 2];
    if (recv_n(sc->sock_fd, header, sizeof(header)) < 0) return SC_ERR_IO;
    if (header[0] != SC_TYPE_DATA) return SC_ERR_PROTO;

    uint64_t seq =
        ((uint64_t)header[1] << 56) | ((uint64_t)header[2] << 48) | ((uint64_t)header[3] << 40) | ((uint64_t)header[4] << 32) |
        ((uint64_t)header[5] << 24) | ((uint64_t)header[6] << 16) | ((uint64_t)header[7] << 8)  | ((uint64_t)header[8]);
    uint16_t len = ((uint16_t)header[9] << 8) | header[10];
    if (len > SC_MAX_RECORD_PLAINTEXT || len > maxlen) return SC_ERR_PARAM;

    if (sc_replay_check_and_set(&sc->rx, seq) != 0) {
        LOG_WARN("sc_recv_data: replay detected seq=%" PRIu64, seq);
        return SC_ERR_REPLAY;
    }

    uint8_t ct[SC_MAX_RECORD_PLAINTEXT];
    if (recv_n(sc->sock_fd, ct, len) < 0) return SC_ERR_IO;
    uint8_t tag[SC_TAG_LEN];
    if (recv_n(sc->sock_fd, tag, sizeof(tag)) < 0) return SC_ERR_IO;

    uint8_t nonce[SC_NONCE_LEN];
    sc_build_nonce(nonce, sc->rx.iv_base, seq);

    if (sc_aead_decrypt(sc->rx.cipher, sc->rx.key, nonce, header, sizeof(header), ct, len, tag, out) != 0) {
        LOG_ERROR("sc_recv_data: AEAD decrypt failed");
        return SC_ERR_CRYPTO;
    }

    return (ssize_t)len;
}

void sc_close(secure_chan_t *sc) {
    if (!sc) return;
    sc_memzero(sc->tx.key, sizeof(sc->tx.key));
    sc_memzero(sc->rx.key, sizeof(sc->rx.key));
    sc_memzero(sc->tx.iv_base, sizeof(sc->tx.iv_base));
    sc_memzero(sc->rx.iv_base, sizeof(sc->rx.iv_base));
    sc_memzero(sc->shared, sizeof(sc->shared));
    sc_memzero(sc->c_priv, sizeof(sc->c_priv));
    sc->is_established = 0;
    LOG_INFO("secure channel closed and secrets wiped");
}

int sc_rekey_if_needed(secure_chan_t *sc, uint64_t bytes_sent, uint64_t secs) {
    (void)sc; (void)bytes_sent; (void)secs;
    /* No-op for now. Application may implement rekey logic and call into
       handshake control messages if desired. */
    return SC_OK;
}

/* hex helper */
int sc_hex2bin(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex || !out) return SC_ERR_PARAM;
    size_t n = strnlen(hex, out_len * 2 + 1);
    if (n != out_len * 2) return SC_ERR_PARAM;
    for (size_t i = 0; i < out_len; ++i) {
        char c1 = hex[2*i], c2 = hex[2*i+1];
        int v1 = (c1>='0'&&c1<='9')?c1-'0':(c1>='a'&&c1<='f')?c1-'a'+10:(c1>='A'&&c1<='F')?c1-'A'+10:-1;
        int v2 = (c2>='0'&&c2<='9')?c2-'0':(c2>='a'&&c2<='f')?c2-'a'+10:(c2>='A'&&c2<='F')?c2-'A'+10:-1;
        if (v1 < 0 || v2 < 0) return SC_ERR_PARAM;
        out[i] = (uint8_t)((v1<<4) | v2);
    }
    return (int)out_len;
}

/* =========================================================
 * OpenSSL crypto helper implementations
 * ========================================================= */

/* Produce a X25519 keypair: outputs raw public and raw private (32 bytes each).
 * Uses EVP_PKEY_keygen on EVP_PKEY_X25519.
 */
static int sc_x25519_keypair(uint8_t pub[32], uint8_t priv[32]) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int rc = -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) { LOG_ERROR("sc_x25519_keypair: EVP_PKEY_CTX_new_id failed"); goto done; }
    if (EVP_PKEY_keygen_init(pctx) <= 0) { LOG_ERROR("sc_x25519_keypair: keygen_init failed"); goto done; }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { LOG_ERROR("sc_x25519_keypair: keygen failed"); goto done; }

    size_t publen = 32, privlen = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &publen) <= 0) { LOG_ERROR("sc_x25519_keypair: get_raw_public failed"); goto done; }
    if (EVP_PKEY_get_raw_private_key(pkey, priv, &privlen) <= 0) { LOG_ERROR("sc_x25519_keypair: get_raw_private failed"); goto done; }
    if (publen != 32 || privlen != 32) { LOG_ERROR("sc_x25519_keypair: unexpected lengths"); goto done; }

    rc = 0;
done:
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (rc != 0) {
        LOG_ERROR("sc_x25519_keypair: OpenSSL error: %s", ERR_error_string(ERR_get_error(), NULL));
    }
    return rc;
}

/* Compute X25519 shared secret: out[32] = X25519(priv, peer_pub) */
static int sc_x25519_shared(uint8_t out[32], const uint8_t priv[32], const uint8_t peer_pub[32]) {
    int rc = -1;
    EVP_PKEY *p_priv = NULL, *p_peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    /* Construct EVP_PKEYs from raw keys */
    p_priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    if (!p_priv) { LOG_ERROR("sc_x25519_shared: new_raw_private_key failed"); goto done; }
    p_peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (!p_peer) { LOG_ERROR("sc_x25519_shared: new_raw_public_key failed"); goto done; }

    ctx = EVP_PKEY_CTX_new(p_priv, NULL);
    if (!ctx) { LOG_ERROR("sc_x25519_shared: EVP_PKEY_CTX_new failed"); goto done; }
    if (EVP_PKEY_derive_init(ctx) <= 0) { LOG_ERROR("sc_x25519_shared: derive_init failed"); goto done; }
    if (EVP_PKEY_derive_set_peer(ctx, p_peer) <= 0) { LOG_ERROR("sc_x25519_shared: derive_set_peer failed"); goto done; }

    size_t outlen = 32;
    if (EVP_PKEY_derive(ctx, out, &outlen) <= 0) { LOG_ERROR("sc_x25519_shared: derive failed"); goto done; }
    if (outlen != 32) { LOG_ERROR("sc_x25519_shared: unexpected shared length %zu", outlen); goto done; }
    rc = 0;
done:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (p_priv) EVP_PKEY_free(p_priv);
    if (p_peer) EVP_PKEY_free(p_peer);
    if (rc != 0) {
        LOG_ERROR("sc_x25519_shared error: %s", ERR_error_string(ERR_get_error(), NULL));
    }
    return rc;
}

/* HKDF expand using OpenSSL EVP_PKEY_CTX HKDF APIs
 * out_len <= ~255*hashlen (we only request 88 bytes)
 */
static int sc_hkdf_expand_openssl(uint8_t *out, size_t out_len,
                                  const uint8_t *salt, size_t salt_len,
                                  const uint8_t *ikm, size_t ikm_len,
                                  const uint8_t *info, size_t info_len) {
    /* Use EVP_PKEY_CTX HKDF APIs (more reliable across OpenSSL versions) */
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) { 
        LOG_ERROR("sc_hkdf_expand_openssl: EVP_PKEY_CTX_new_id failed"); 
        return SC_ERR_CRYPTO; 
    }
    
    if (EVP_PKEY_derive_init(pctx) <= 0) { 
        EVP_PKEY_CTX_free(pctx); 
        return SC_ERR_CRYPTO; 
    }
    
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0) { 
        EVP_PKEY_CTX_free(pctx); 
        return SC_ERR_CRYPTO; 
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0) { 
        EVP_PKEY_CTX_free(pctx); 
        return SC_ERR_CRYPTO; 
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) { 
        EVP_PKEY_CTX_free(pctx); 
        return SC_ERR_CRYPTO; 
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) <= 0) { 
        EVP_PKEY_CTX_free(pctx); 
        return SC_ERR_CRYPTO; 
    }
    
    if (info && info_len) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) { 
            EVP_PKEY_CTX_free(pctx); 
            return SC_ERR_CRYPTO; 
        }
    }
    
    size_t olen = out_len;
    if (EVP_PKEY_derive(pctx, out, &olen) <= 0) { 
        EVP_PKEY_CTX_free(pctx); 
        return SC_ERR_CRYPTO; 
    }
    
    EVP_PKEY_CTX_free(pctx);
    return 0;
}

/* AEAD encryption using OpenSSL EVP interfaces
 * Supports ChaCha20-Poly1305 and AES-256-GCM
 * ct buffer must be at least pt_len bytes
 */
static int sc_aead_encrypt(sc_cipher_t c,
                           const uint8_t key[32], const uint8_t nonce[SC_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct, uint8_t tag[SC_TAG_LEN]) {
    const EVP_CIPHER *cipher = NULL;
    if (c == SC_CIPHER_CHACHA20_POLY1305) cipher = EVP_chacha20_poly1305();
    else if (c == SC_CIPHER_AES_256_GCM) cipher = EVP_aes_256_gcm();
    else { LOG_ERROR("sc_aead_encrypt: unknown cipher"); return SC_ERR_CRYPTO; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { LOG_ERROR("sc_aead_encrypt: ctx new failed"); return SC_ERR_CRYPTO; }

    int rc = SC_ERR_CRYPTO;
    int outlen = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) { LOG_ERROR("EncryptInit failed"); goto done; }
    /* Set key and nonce length if required */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, SC_NONCE_LEN, NULL) != 1) { LOG_ERROR("set ivlen failed"); goto done; }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) { LOG_ERROR("set key/iv failed"); goto done; }
    if (aad && aad_len) {
        if (EVP_EncryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len) != 1) { LOG_ERROR("AAD update failed"); goto done; }
    }

    if (pt && pt_len) {
        if (EVP_EncryptUpdate(ctx, ct, &outlen, pt, (int)pt_len) != 1) { LOG_ERROR("EncryptUpdate failed"); goto done; }
    }

    int finlen = 0;
    if (EVP_EncryptFinal_ex(ctx, ct + outlen, &finlen) != 1) { LOG_ERROR("EncryptFinal failed"); goto done; }
    outlen += finlen;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, SC_TAG_LEN, tag) != 1) { LOG_ERROR("get tag failed"); goto done; }

    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 0) LOG_ERROR("sc_aead_encrypt err: %s", ERR_error_string(ERR_get_error(), NULL));
    return rc;
}

/* AEAD decrypt */
static int sc_aead_decrypt(sc_cipher_t c,
                           const uint8_t key[32], const uint8_t nonce[SC_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[SC_TAG_LEN],
                           uint8_t *pt) {
    const EVP_CIPHER *cipher = NULL;
    if (c == SC_CIPHER_CHACHA20_POLY1305) cipher = EVP_chacha20_poly1305();
    else if (c == SC_CIPHER_AES_256_GCM) cipher = EVP_aes_256_gcm();
    else { LOG_ERROR("sc_aead_decrypt: unknown cipher"); return SC_ERR_CRYPTO; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { LOG_ERROR("sc_aead_decrypt: ctx new failed"); return SC_ERR_CRYPTO; }

    int rc = SC_ERR_CRYPTO;
    int outlen = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) { LOG_ERROR("DecryptInit failed"); goto done; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, SC_NONCE_LEN, NULL) != 1) { LOG_ERROR("set ivlen failed"); goto done; }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) { LOG_ERROR("set key/iv failed"); goto done; }
    if (aad && aad_len) {
        if (EVP_DecryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len) != 1) { LOG_ERROR("AAD update failed"); goto done; }
    }
    if (ct && ct_len) {
        if (EVP_DecryptUpdate(ctx, pt, &outlen, ct, (int)ct_len) != 1) { LOG_ERROR("DecryptUpdate failed"); goto done; }
    }
    /* Set expected tag before final */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, SC_TAG_LEN, (void*)tag) != 1) { LOG_ERROR("set tag failed"); goto done; }
    if (EVP_DecryptFinal_ex(ctx, pt + outlen, &outlen) != 1) { LOG_ERROR("DecryptFinal failed (auth)"); goto done; }

    rc = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 0) LOG_ERROR("sc_aead_decrypt err: %s", ERR_error_string(ERR_get_error(), NULL));
    return rc;
}
