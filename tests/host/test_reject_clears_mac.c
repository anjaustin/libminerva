/**
 * @file test_reject_clears_mac.c
 * @brief A rejected inference invalidates the output attestation (red-team Fix 4).
 *
 * The output-MAC state (has_output_mac / output_mac) was cleared on the
 * glitch/mismatch fail path but NOT on the input-validation and confidence
 * early returns, so a prior success's attestation survived a later rejection —
 * an inconsistent, per-failure-type attestation lifetime. The fix routes those
 * early returns through the fail label.
 *
 * This test drives a real confidence rejection: weights are saturated so a
 * large input yields max-logit 127 (accepted at MNV_MIN_CONFIDENCE=100) and a
 * zero input yields logit 0 (rejected). After the rejection, verifying the
 * PRIOR genuine output must now fail (attestation invalidated). Observed purely
 * via mnv_verify_output() / mnv_run() return values.
 *
 * Built with -DMNV_MIN_CONFIDENCE=100 (see run_engine_tests.sh).
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
    printf("  %-56s %s\n", (msg), _ok ? "PASS" : "FAIL"); \
    if (!_ok) fails++; } while (0)

#define IN  MNV_INPUT_SIZE
#define H0  MNV_LAYER_0_SIZE
#define H1  MNV_LAYER_1_SIZE
#define OUT MNV_OUTPUT_SIZE
#define W0N (H0*IN)
#define W1N (H1*H0)
#define W2N (OUT*H1)
#define PT_LEN (W0N+H0 + W1N+H1 + W2N+OUT)

static int8_t W0[W0N], b0[H0], W1[W1N], b1[H1], W2[W2N], b2[OUT];

int main(void)
{
    printf("[reject clears attestation, MNV_MIN_CONFIDENCE=%d]\n", MNV_MIN_CONFIDENCE);
    /* Saturating positive weights, zero bias: large input -> logit 127,
     * zero input -> logit 0. */
    memset(W0, 127, sizeof(W0)); memset(W1, 127, sizeof(W1)); memset(W2, 127, sizeof(W2));
    memset(b0, 0, sizeof(b0));   memset(b1, 0, sizeof(b1));   memset(b2, 0, sizeof(b2));

    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 5);
    uint8_t nonce[12] = {0}; nonce[0] = 0x11;
    static uint8_t pt[PT_LEN], ct[PT_LEN]; uint8_t mac[32];
    size_t o = 0;
    memcpy(pt+o, W0, W0N); o += W0N; memcpy(pt+o, b0, H0); o += H0;
    memcpy(pt+o, W1, W1N); o += W1N; memcpy(pt+o, b1, H1); o += H1;
    memcpy(pt+o, W2, W2N); o += W2N; memcpy(pt+o, b2, OUT);
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
    CHECK(mnv_init(&ctx, &M) == MNV_OK, "init -> OK");

    /* High-confidence success. */
    int8_t inA[IN], outA[OUT];
    for (int i = 0; i < IN; i++) inA[i] = 127;
    CHECK(mnv_run(&ctx, inA, outA) == MNV_OK, "high-confidence run -> OK");
    CHECK(mnv_verify_output(&ctx, inA, outA) == MNV_OK, "verify prior output -> OK");

    /* Low-confidence input -> rejected. */
    int8_t inB[IN] = {0}, outB[OUT];
    CHECK(mnv_run(&ctx, inB, outB) == MNV_ERR_CONFIDENCE, "low-confidence run -> CONFIDENCE");

    /* The prior genuine attestation must now be invalidated (Fix 4). Pre-fix
     * this returned OK (the rejection left has_output_mac / output_mac intact). */
    CHECK(mnv_verify_output(&ctx, inA, outA) == MNV_ERR_TAMPER,
          "verify prior output AFTER rejection -> TAMPER");

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
