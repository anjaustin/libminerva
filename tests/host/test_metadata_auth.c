/**
 * @file test_metadata_auth.c
 * @brief Regression for the structural-authentication fix (audit finding F1).
 *
 * Before the fix, the integrity MAC covered only the ciphertext blob, so an
 * attacker who could rewrite the flash image (in scope per threat_model.md
 * §3.1) could change the model's STRUCTURE — a layer's activation, an interior
 * width, or num_layers — without invalidating the MAC, altering inference
 * behavior while mnv_init() still returned MNV_OK. See src/security/mnv_struct_auth.h.
 *
 * This test builds a genuine encrypted+MAC'd MLP in memory, then mutates ONLY
 * structural metadata (never the ciphertext or the stored MAC) and asserts each
 * mutation is now rejected with MNV_ERR_TAMPER. A ciphertext-byte flip is the
 * control (proves the MAC still works and the metadata cases aren't a broken
 * MAC), and an identical fresh descriptor copy is the negative control (proves
 * detection comes from the mutation, not from copying the array).
 *
 * Build: see tests/host/run_engine_tests.sh (metadata_auth config).
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

#define IN   MNV_INPUT_SIZE
#define H0   MNV_LAYER_0_SIZE
#define H1   MNV_LAYER_1_SIZE
#define OUT  MNV_OUTPUT_SIZE
#define W0N (H0*IN)
#define W1N (H1*H0)
#define W2N (OUT*H1)
#define PT_LEN (W0N + H0 + W1N + H1 + W2N + OUT)

int main(void) {
    printf("[metadata-auth MLP %d->%d->%d->%d]\n", IN, H0, H1, OUT);

    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i*11+2);
    uint8_t nonce[12] = {0}; nonce[0] = 0xa5;

    static uint8_t pt[PT_LEN], ct[PT_LEN]; uint8_t mac[32];
    for (int i = 0; i < PT_LEN; i++) pt[i] = (uint8_t)((i*7+3) & 0xFF);   /* arbitrary weights */

    uint8_t k_enc[32], k_mac[32];
    mnv_kdf_derive(key, MNV_KDF_LABEL_ENC, k_enc);
    mnv_kdf_derive(key, MNV_KDF_LABEL_MAC, k_mac);
    mnv_chacha20_ctx_t cc; mnv_chacha20_init(&cc, k_enc, nonce, 0);
    mnv_chacha20_decrypt(&cc, pt, ct, PT_LEN);                 /* XOR == encrypt */

    mnv_crypto_header_t H; memcpy(H.iv, nonce, 12);
    H.weight_count = W0N+W1N+W2N; H.bias_count = H0+H1+OUT;
    mnv_layer_desc_t L[3] = {
        { IN, H0,  MNV_ACT_RELU,   NULL, NULL },
        { H0, H1,  MNV_ACT_RELU,   NULL, NULL },
        { H1, OUT, MNV_ACT_LINEAR, NULL, NULL },
    };
    mnv_model_t M = { MNV_ABI_VERSION, 3, L, &H, key, ct, PT_LEN };
    test_blob_mac(&M, k_mac, ct, PT_LEN, mac); memcpy(H.mac, mac, 32);

    /* Genuine model verifies. */
    static mnv_ctx_t ctx;
    CHECK(mnv_init(&ctx, &M) == MNV_OK, "genuine model init -> OK");

    /* Negative control: an identical fresh descriptor array still verifies (so a
     * TAMPER below is due to the mutation, not to using a copy). */
    {
        mnv_layer_desc_t Lc[3]; memcpy(Lc, L, sizeof(Lc));
        mnv_model_t Mc = M; Mc.layers = Lc;
        static mnv_ctx_t cx;
        CHECK(mnv_init(&cx, &Mc) == MNV_OK, "identical descriptor copy init -> OK");
    }

    /* (1) Flip a hidden layer's activation (ciphertext + MAC untouched). */
    {
        mnv_layer_desc_t Lt[3]; memcpy(Lt, L, sizeof(Lt));
        Lt[1].activation = MNV_ACT_TANH;                       /* was RELU */
        mnv_model_t Mt = M; Mt.layers = Lt;
        static mnv_ctx_t cx;
        CHECK(mnv_init(&cx, &Mt) == MNV_ERR_TAMPER,
              "activation flip (RELU->TANH) -> TAMPER");
    }

    /* (2) Change an interior width (stays within the topology-guard bounds, so
     *     it reaches the MAC rather than being caught as MNV_ERR_CONFIG). */
    {
        mnv_layer_desc_t Lt[3]; memcpy(Lt, L, sizeof(Lt));
        Lt[0].output_size = (uint16_t)(H0 - 1);
        mnv_model_t Mt = M; Mt.layers = Lt;
        static mnv_ctx_t cx;
        CHECK(mnv_init(&cx, &Mt) == MNV_ERR_TAMPER,
              "interior width change -> TAMPER");
    }

    /* (3) Collapse the network to a single linear layer (valid input/output
     *     widths, so it clears the topology guard). */
    {
        mnv_layer_desc_t L1[1] = { { IN, OUT, MNV_ACT_LINEAR, NULL, NULL } };
        mnv_model_t Mt = M; Mt.num_layers = 1; Mt.layers = L1;
        static mnv_ctx_t cx;
        CHECK(mnv_init(&cx, &Mt) == MNV_ERR_TAMPER,
              "collapse to 1 linear layer (num_layers) -> TAMPER");
    }

    /* (4) Control: a single ciphertext byte flip must be caught by the MAC. */
    {
        static uint8_t ctb[PT_LEN]; memcpy(ctb, ct, PT_LEN); ctb[0] ^= 0x01;
        mnv_model_t Mt = M; Mt.encrypted_weights = ctb;
        static mnv_ctx_t cx;
        CHECK(mnv_init(&cx, &Mt) == MNV_ERR_TAMPER,
              "control: 1 ciphertext byte -> TAMPER");
    }

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
