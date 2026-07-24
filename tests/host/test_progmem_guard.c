/**
 * @file test_progmem_guard.c
 * @brief PROGMEM chunk-read path + AVR >64 KB near-pointer guard (Item 4).
 *
 * Built with MNV_PROGMEM_WEIGHTS forced on (host pgm_read_byte is a no-op), so
 * this exercises the AVR flash path in mnv_init() — the 64-byte chunked
 * BLAKE2s read — which the true-host engine tests no longer cover. It then
 * checks that a model claiming an encrypted_len > 64 KB is rejected with
 * MNV_ERR_CONFIG rather than wrapping a 16-bit flash pointer.
 *
 * Topology comes from -D macros (see run_engine_tests.sh).
 */
#define MNV_TARGET_HOST
#include "minerva.h"
#include "mnv_chacha20.h"
#include "mnv_blake2s.h"
#include "mnv_kdf.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    int _ok = (cond); \
    printf("  %-52s %s\n", (msg), _ok ? "PASS" : "FAIL"); \
    if (!_ok) fails++; } while (0)

#define IN   MNV_INPUT_SIZE
#define H0   MNV_LAYER_0_SIZE
#define H1   MNV_LAYER_1_SIZE
#define OUT  MNV_OUTPUT_SIZE
#define W0N (H0*IN)
#define W1N (H1*H0)
#define W2N (OUT*H1)
#define PT_LEN (W0N + H0 + W1N + H1 + W2N + OUT)

static int8_t W0[W0N], b0[H0], W1[W1N], b1[H1], W2[W2N], b2[OUT];

static void serialize(uint8_t *pt) {
    size_t o = 0;
    memcpy(pt+o, W0, W0N); o += W0N;  memcpy(pt+o, b0, H0); o += H0;
    memcpy(pt+o, W1, W1N); o += W1N;  memcpy(pt+o, b1, H1); o += H1;
    memcpy(pt+o, W2, W2N); o += W2N;  memcpy(pt+o, b2, OUT);
}

int main(void) {
    printf("[progmem guard MLP %d->%d->%d->%d]\n", IN, H0, H1, OUT);
    for (int i = 0; i < W0N; i++) W0[i] = (int8_t)((i % 5) - 2);
    for (int i = 0; i < H0;  i++) b0[i] = 1;
    for (int i = 0; i < W1N; i++) W1[i] = (int8_t)((i % 3) - 1);
    for (int i = 0; i < H1;  i++) b1[i] = 0;
    for (int i = 0; i < W2N; i++) W2[i] = (int8_t)((i % 4) - 1);
    for (int i = 0; i < OUT; i++) b2[i] = 0;

    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i*3+5);
    uint8_t nonce[12] = {0}; nonce[0] = 0xA5;

    static uint8_t pt[PT_LEN], ct[PT_LEN]; uint8_t mac[32];
    serialize(pt);
    uint8_t k_enc[32], k_mac[32];
    mnv_kdf_derive(key, MNV_KDF_LABEL_ENC, k_enc);   /* domain separation (mnv_kdf.h) */
    mnv_kdf_derive(key, MNV_KDF_LABEL_MAC, k_mac);
    mnv_chacha20_ctx_t cc; mnv_chacha20_init(&cc, k_enc, nonce, 0);
    mnv_chacha20_decrypt(&cc, pt, ct, PT_LEN);
    mnv_blake2s_mac(k_mac, 32, ct, PT_LEN, mac);

    mnv_crypto_header_t H; memcpy(H.iv, nonce, 12); memcpy(H.mac, mac, 32);
    H.weight_count = W0N+W1N+W2N; H.bias_count = H0+H1+OUT;
    mnv_layer_desc_t L[3] = {
        { IN, H0, MNV_ACT_RELU,   NULL, NULL },
        { H0, H1, MNV_ACT_RELU,   NULL, NULL },
        { H1, OUT, MNV_ACT_LINEAR, NULL, NULL },
    };
    mnv_model_t M = { MNV_ABI_VERSION, 3, L, &H, key, ct, PT_LEN };

    static mnv_ctx_t ctx;
    /* Valid init exercises the 64-byte chunked pgm_read_byte MAC loop. */
    CHECK(mnv_init(&ctx, &M) == MNV_OK, "init valid model via PROGMEM read -> OK");

    /* A run should still succeed through the PROGMEM decrypt path. */
    {
        int8_t in[IN], out[OUT];
        for (int i = 0; i < IN; i++) in[i] = (int8_t)(i - 3);
        CHECK(mnv_run(&ctx, in, out) == MNV_OK, "run via PROGMEM decrypt -> OK");
    }

    /* Re-verification (mnv_verify) must use the same chunked pgm_read path, not
     * a direct memcpy of the PROGMEM blob. ct is what M.encrypted_weights points
     * to, so tampering it in place and restoring exercises both outcomes. */
    CHECK(mnv_verify(&ctx, &M) == MNV_OK, "re-verify via PROGMEM read -> OK");
    ct[7] ^= 0x08;
    CHECK(mnv_verify(&ctx, &M) == MNV_ERR_TAMPER,
          "re-verify tampered blob via PROGMEM read -> TAMPER");
    ct[7] ^= 0x08;  /* restore */

    /* AVR near-pointer guard: a blob claiming > 64 KB must be rejected up front
     * (before any flash read), because pgm_read_byte uses a 16-bit pointer. */
    {
        mnv_model_t Mbig = M; Mbig.encrypted_len = 0x10000UL;  /* 65536 */
        static mnv_ctx_t ctx_big;
        CHECK(mnv_init(&ctx_big, &Mbig) == MNV_ERR_CONFIG,
              "init blob > 64 KB under PROGMEM -> CONFIG (before any read)");
    }

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
