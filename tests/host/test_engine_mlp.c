/**
 * @file test_engine_mlp.c
 * @brief End-to-end MLP engine test (host).
 *
 * Builds a real ChaCha20-encrypted, BLAKE2s-MAC'd model in memory, runs it
 * through the full mnv_init() + mnv_run() pipeline, and compares the output
 * against an INDEPENDENT integer reference implementation (so a bug in the
 * engine's arithmetic is actually caught, not mirrored).
 *
 * Also exercises the negative paths: tamper, null args, out-of-range input.
 *
 * Topology is taken from the MNV_* macros, so the same source can be compiled
 * for different shapes (see run_engine_tests.sh).
 *
 * Build: see tests/host/run_engine_tests.sh for the canonical invocation
 * (compiles this TU with the engine + security sources under ASan/UBSan).
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
    printf("  %-52s %s\n", (msg), _ok ? "PASS" : "FAIL"); \
    if (!_ok) fails++; } while (0)

/* ── topology ─────────────────────────────────────────────────────────────── */
#define IN   MNV_INPUT_SIZE
#define H0   MNV_LAYER_0_SIZE
#define H1   MNV_LAYER_1_SIZE
#define OUT  MNV_OUTPUT_SIZE

/* weight blob: W0[H0*IN] b0[H0] W1[H1*H0] b1[H1] W2[OUT*H1] b2[OUT] */
#define W0N (H0*IN)
#define W1N (H1*H0)
#define W2N (OUT*H1)
#define PT_LEN (W0N + H0 + W1N + H1 + W2N + OUT)

/* plaintext weight/bias storage, row-major weight[out*in + in_idx] */
static int8_t W0[W0N], b0[H0], W1[W1N], b1[H1], W2[W2N], b2[OUT];

/* deterministic small pseudo-random fill, reproducible across runs */
static uint32_t lcg_state = 0x1234567u;
static int8_t small_rand(int lo, int hi) {
    lcg_state = lcg_state * 1103515245u + 12345u;
    int span = hi - lo + 1;
    return (int8_t)(lo + (int)((lcg_state >> 16) % (uint32_t)span));
}

static void fill_weights(void) {
    for (int i = 0; i < W0N; i++) W0[i] = small_rand(-3, 3);
    for (int i = 0; i < H0;  i++) b0[i] = small_rand(-2, 2);
    for (int i = 0; i < W1N; i++) W1[i] = small_rand(-3, 3);
    for (int i = 0; i < H1;  i++) b1[i] = small_rand(-2, 2);
    for (int i = 0; i < W2N; i++) W2[i] = small_rand(-3, 3);
    for (int i = 0; i < OUT; i++) b2[i] = small_rand(-2, 2);
}

/* ── independent integer reference (mirrors engine semantics) ─────────────── */
static int8_t clamp8(int32_t x) {
    if (x >  127) return  127;
    if (x < -128) return -128;
    return (int8_t)x;
}
static void ref_layer(const int8_t *W, const int8_t *b, const int8_t *x,
                      int8_t *y, int in_sz, int out_sz, int relu) {
    for (int n = 0; n < out_sz; n++) {
        int32_t acc = 0;
        for (int i = 0; i < in_sz; i++)
            acc += (int32_t)W[n*in_sz + i] * (int32_t)x[i];
        int8_t v = clamp8((acc >> 7) + (int32_t)b[n]);
        y[n] = relu ? (v < 0 ? 0 : v) : v;
    }
}
static void reference_forward(const int8_t *in, int8_t *out) {
    int8_t h0[H0], h1[H1];
    ref_layer(W0, b0, in, h0, IN, H0, 1);
    ref_layer(W1, b1, h0, h1, H0, H1, 1);
    ref_layer(W2, b2, h1, out, H1, OUT, 0);
}

/* ── model construction ───────────────────────────────────────────────────── */
static void serialize(uint8_t *pt) {
    size_t o = 0;
    memcpy(pt+o, W0, W0N); o += W0N;  memcpy(pt+o, b0, H0); o += H0;
    memcpy(pt+o, W1, W1N); o += W1N;  memcpy(pt+o, b1, H1); o += H1;
    memcpy(pt+o, W2, W2N); o += W2N;  memcpy(pt+o, b2, OUT);
}

int main(void) {
    printf("[engine MLP %d->%d->%d->%d]\n", IN, H0, H1, OUT);
    fill_weights();

    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i*7+1);
    uint8_t nonce[12] = {0}; nonce[0] = 0x5a;

    static uint8_t pt[PT_LEN], ct[PT_LEN]; uint8_t mac[32];
    serialize(pt);
    /* Build the blob with the derived subkeys (the engine derives the same from
     * the master key it is handed in M below — key domain separation, mnv_kdf.h). */
    uint8_t k_enc[32], k_mac[32];
    mnv_kdf_derive(key, MNV_KDF_LABEL_ENC, k_enc);
    mnv_kdf_derive(key, MNV_KDF_LABEL_MAC, k_mac);
    mnv_chacha20_ctx_t cc; mnv_chacha20_init(&cc, k_enc, nonce, 0);
    mnv_chacha20_decrypt(&cc, pt, ct, PT_LEN);              /* XOR == encrypt */

    mnv_crypto_header_t H; memcpy(H.iv, nonce, 12);
    H.weight_count = W0N+W1N+W2N; H.bias_count = H0+H1+OUT;
    mnv_layer_desc_t L[3] = {
        { IN, H0, MNV_ACT_RELU,   NULL, NULL },
        { H0, H1, MNV_ACT_RELU,   NULL, NULL },
        { H1, OUT, MNV_ACT_LINEAR, NULL, NULL },
    };
    mnv_model_t M = { MNV_ABI_VERSION, 3, L, &H, key, ct, PT_LEN };
    /* MAC covers S(structure) || ciphertext — compute after M exists. */
    test_blob_mac(&M, k_mac, ct, PT_LEN, mac); memcpy(H.mac, mac, 32);

    static mnv_ctx_t ctx;
    CHECK(mnv_init(&ctx, &M) == MNV_OK, "init valid model -> OK");

    /* Item 9: verifying an output before any inference (counter == 0) must be
     * rejected cleanly, not underflow the counter. */
    {
        int8_t din[IN] = {0}, dout[OUT] = {0};
        CHECK(mnv_verify_output(&ctx, din, dout) == MNV_ERR_TAMPER,
              "verify_output before any run -> TAMPER");
    }

    /* correctness across several inputs */
    int correctness_ok = 1;
    for (int t = 0; t < 8; t++) {
        int8_t in[IN], out[OUT], ref[OUT];
        for (int i = 0; i < IN; i++) in[i] = small_rand(-40, 40);
        if (mnv_run(&ctx, in, out) != MNV_OK) { correctness_ok = 0; break; }
        reference_forward(in, ref);
        if (memcmp(out, ref, OUT) != 0) {
            correctness_ok = 0;
            printf("    mismatch t=%d: engine[", t);
            for (int i=0;i<OUT;i++) printf("%d ", out[i]);
            printf("] ref[");
            for (int i=0;i<OUT;i++) printf("%d ", ref[i]);
            printf("]\n");
            break;
        }
    }
    CHECK(correctness_ok, "engine output == independent reference (8 inputs)");

    /* output auth round-trips on the last run */
    {
        int8_t in[IN], out[OUT];
        for (int i = 0; i < IN; i++) in[i] = small_rand(-40, 40);
        CHECK(mnv_run(&ctx, in, out) == MNV_OK, "run -> OK");
        CHECK(mnv_verify_output(&ctx, in, out) == MNV_OK, "verify_output -> OK");
        int8_t bad[OUT]; memcpy(bad, out, OUT); bad[0] ^= 1;
        CHECK(mnv_verify_output(&ctx, in, bad) == MNV_ERR_TAMPER,
              "verify_output tampered -> TAMPER");
    }

    /* negative paths */
    {
        int8_t in[IN] = {0}, out[OUT] = {0};
        CHECK(mnv_run(NULL, in, out) == MNV_ERR_NULL, "run NULL ctx -> NULL");
        CHECK(mnv_run(&ctx, NULL, out) == MNV_ERR_NULL, "run NULL input -> NULL");

        /* tamper: flip one ciphertext byte, fresh context */
        static uint8_t ct_bad[PT_LEN]; memcpy(ct_bad, ct, PT_LEN); ct_bad[33] ^= 0x80;
        mnv_model_t Mt = { MNV_ABI_VERSION, 3, L, &H, key, ct_bad, PT_LEN };
        static mnv_ctx_t ctx_t;
        CHECK(mnv_init(&ctx_t, &Mt) == MNV_ERR_TAMPER, "init flipped ct -> TAMPER");

        /* bad ABI version */
        mnv_model_t Mv = M; Mv.version = 0xFF;
        static mnv_ctx_t ctx_v;
        CHECK(mnv_init(&ctx_v, &Mv) == MNV_ERR_CONFIG, "init bad ABI -> CONFIG");

        /* topology guard: a model whose declared input width disagrees with the
         * compiled-in MNV_INPUT_SIZE must be rejected (would otherwise mis-size
         * ctx buffers). This is the runtime backstop for the mnv_model_dims.h /
         * __has_include propagation. */
        mnv_layer_desc_t Lbad[3] = {
            { IN + 1, H0,  MNV_ACT_RELU,   NULL, NULL },  /* wrong input_size */
            { H0,     H1,  MNV_ACT_RELU,   NULL, NULL },
            { H1,     OUT, MNV_ACT_LINEAR, NULL, NULL },
        };
        mnv_model_t Mbad = M; Mbad.layers = Lbad;
        static mnv_ctx_t ctx_b;
        CHECK(mnv_init(&ctx_b, &Mbad) == MNV_ERR_CONFIG,
              "init topology mismatch -> CONFIG");

        /* and a last-layer output-width mismatch */
        mnv_layer_desc_t Lbad2[3] = {
            { IN, H0,      MNV_ACT_RELU,   NULL, NULL },
            { H0, H1,      MNV_ACT_RELU,   NULL, NULL },
            { H1, OUT + 1, MNV_ACT_LINEAR, NULL, NULL },  /* wrong output_size */
        };
        mnv_model_t Mbad2 = M; Mbad2.layers = Lbad2;
        static mnv_ctx_t ctx_b2;
        CHECK(mnv_init(&ctx_b2, &Mbad2) == MNV_ERR_CONFIG,
              "init output-width mismatch -> CONFIG");
    }

    /* (The counter-wraparound behavior of the output MAC is covered directly
     * and reliably in tests/host/test_outauth_counter.c — driving it through
     * mnv_run here made the assertion hostage to the double-run path and to
     * compilers caching the white-box ctx read.) */

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
