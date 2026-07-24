/**
 * @file test_progmem_split.c
 * @brief PROGMEM access-pattern lock (H3): the engine must read the encrypted
 *        weight blob ONLY through pgm_read, never a direct dereference.
 *
 * Built with -include pgm_shim.h and -DMNV_PROGMEM_WEIGHTS. The model's
 * encrypted_weights points at a POISONED buffer; mnv_test_pgm_read redirects
 * reads of that range to the REAL ciphertext. So:
 *   - a correct engine (blob via pgm_read) sees real data  -> init/run/verify OK
 *   - a regressed engine (direct blob read) sees poison     -> MAC fails
 * The crypto header and layer descriptors are ordinary RAM structs (read
 * directly, which is what the AVR fix requires); the poison covers only the
 * blob. So this locks: (a) mnv_init MAC, (b) mnv_verify MAC, (c) the forward-pass
 * decrypt all go through pgm_read for the blob.
 */
#ifndef MNV_TARGET_HOST      /* may be passed via -D */
#define MNV_TARGET_HOST
#endif
#include "minerva.h"
#include "mnv_chacha20.h"
#include "mnv_blake2s.h"
#include "mnv_kdf.h"
#include "test_blob_mac.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    int _ok = (cond); \
    printf("  %-56s %s\n", (msg), _ok ? "PASS" : "FAIL"); \
    if (!_ok) fails++; } while (0)

#define IN 8
#define H0 8
#define H1 8
#define OUT 4
#define W0N (H0*IN)
#define W1N (H1*H0)
#define W2N (OUT*H1)
#define PT_LEN (W0N+H0 + W1N+H1 + W2N+OUT)

/* Real ciphertext ("flash contents") and the poisoned copy the model points at. */
static uint8_t real_ct[PT_LEN];
static uint8_t poison_ct[PT_LEN];

/* Redirect reads of the poisoned blob range to the real bytes; everything else
 * (LUT tables, etc.) reads directly. */
uint8_t mnv_test_pgm_read(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    if (b >= poison_ct && b < poison_ct + PT_LEN)
        return real_ct[b - poison_ct];
    return *b;
}

int main(void)
{
    printf("[progmem access-pattern lock: blob must be read via pgm_read]\n");
    static int8_t W0[W0N], b0[H0], W1[W1N], b1[H1], W2[W2N], b2[OUT];
    for (int i = 0; i < W0N; i++) W0[i] = (int8_t)((i % 5) - 2);
    for (int i = 0; i < W1N; i++) W1[i] = (int8_t)((i % 3) - 1);
    for (int i = 0; i < W2N; i++) W2[i] = (int8_t)((i % 4) - 1);

    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 2);
    uint8_t nonce[12] = {0}; nonce[0] = 0xC3;
    static uint8_t pt[PT_LEN]; uint8_t mac[32];
    size_t o = 0;
    memcpy(pt+o, W0, W0N); o += W0N; memcpy(pt+o, b0, H0); o += H0;
    memcpy(pt+o, W1, W1N); o += W1N; memcpy(pt+o, b1, H1); o += H1;
    memcpy(pt+o, W2, W2N); o += W2N; memcpy(pt+o, b2, OUT);
    uint8_t k_enc[32], k_mac[32];
    mnv_kdf_derive(key, MNV_KDF_LABEL_ENC, k_enc);         /* domain separation */
    mnv_kdf_derive(key, MNV_KDF_LABEL_MAC, k_mac);
    mnv_chacha20_ctx_t cc; mnv_chacha20_init(&cc, k_enc, nonce, 0);
    mnv_chacha20_decrypt(&cc, pt, real_ct, PT_LEN);        /* real ciphertext */

    /* Poison the blob the model actually points at (so a direct read is wrong). */
    for (int i = 0; i < PT_LEN; i++) poison_ct[i] = (uint8_t)(real_ct[i] ^ 0xFF);

    mnv_crypto_header_t H; memcpy(H.iv, nonce, 12);
    H.weight_count = W0N+W1N+W2N; H.bias_count = H0+H1+OUT;
    mnv_layer_desc_t L[3] = {
        { IN, H0, MNV_ACT_RELU,   NULL, NULL },
        { H0, H1, MNV_ACT_RELU,   NULL, NULL },
        { H1, OUT, MNV_ACT_LINEAR, NULL, NULL },
    };
    mnv_model_t M = { MNV_ABI_VERSION, 3, L, &H, key, poison_ct, PT_LEN };
    /* MAC over S || REAL ciphertext (engine reads real via the pgm_read shim). */
    test_blob_mac(&M, k_mac, real_ct, PT_LEN, mac); memcpy(H.mac, mac, 32);

    static mnv_ctx_t ctx;
    /* If mnv_init read the blob directly it would MAC the poison -> TAMPER. OK
     * proves it went through pgm_read. */
    CHECK(mnv_init(&ctx, &M) == MNV_OK, "init reads blob via pgm_read -> OK");

    int8_t in[IN], out[OUT];
    for (int i = 0; i < IN; i++) in[i] = (int8_t)(i - 3);
    CHECK(mnv_run(&ctx, in, out) == MNV_OK, "run decrypts blob via pgm_read -> OK");

    CHECK(mnv_verify(&ctx, &M) == MNV_OK, "re-verify reads blob via pgm_read -> OK");

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
