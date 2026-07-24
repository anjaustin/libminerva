/**
 * @file test_fuzz_init.c
 * @brief Deterministic fuzz harness for mnv_init() (R4).
 *
 * Builds one genuine ChaCha20-encrypted, BLAKE2s-MAC'd MLP, then hammers
 * mnv_init() with single-field mutations of a *copy* of the model — every field
 * an attacker with flash-write could touch: version, num_layers, each layer's
 * size/activation, the crypto header (iv, mac, counts), the device key,
 * ciphertext bytes, and encrypted_len (including out-of-range values).
 *
 * Invariants (checked every iteration, under ASan + UBSan):
 *   1. mnv_init() never crashes / reads out of bounds on any mutated input.
 *   2. mnv_init() returns MNV_OK *only* for the pristine model — every mutation
 *      that changes an authenticated field is rejected (now that structure, IV,
 *      and counts are all in S, nothing tampered slips through).
 *
 * The blob lives in an over-allocated buffer (like readable MCU flash), so an
 * enlarged encrypted_len reads valid memory and fails the MAC rather than
 * faulting; a grossly out-of-range length is rejected by mnv_init's bound.
 *
 * Build: see tests/host/run_engine_tests.sh (fuzz_init config).
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
    if (!_ok) { printf("  FAIL: %s\n", (msg)); fails++; } } while (0)

#define IN   MNV_INPUT_SIZE
#define H0   MNV_LAYER_0_SIZE
#define H1   MNV_LAYER_1_SIZE
#define OUT  MNV_OUTPUT_SIZE
#define W0N (H0*IN)
#define W1N (H1*H0)
#define W2N (OUT*H1)
#define PT_LEN (W0N + H0 + W1N + H1 + W2N + OUT)
#define CAP    4096u          /* over-allocated blob buffer (>= PT_LEN) */

#ifndef FUZZ_ITERS
#define FUZZ_ITERS 200000u
#endif

static uint32_t rng = 0xC0FFEEu;
static uint32_t nxt(void){ rng = rng*1103515245u + 12345u; return rng; }
static uint32_t rr(uint32_t n){ return nxt() % n; }

int main(void) {
    printf("[fuzz mnv_init: %u iterations, MLP %d->%d->%d->%d]\n",
           (unsigned)FUZZ_ITERS, IN, H0, H1, OUT);

    /* ── genuine model ── */
    uint8_t key[32]; for (int i=0;i<32;i++) key[i]=(uint8_t)(i*9+4);
    uint8_t nonce[12]={0}; nonce[0]=0x3c;
    static uint8_t pt[PT_LEN]; static uint8_t ct[CAP]; uint8_t mac[32];
    for (int i=0;i<PT_LEN;i++) pt[i]=(uint8_t)((i*13+5)&0xFF);

    uint8_t k_enc[32], k_mac[32];
    mnv_kdf_derive(key, MNV_KDF_LABEL_ENC, k_enc);
    mnv_kdf_derive(key, MNV_KDF_LABEL_MAC, k_mac);
    mnv_chacha20_ctx_t cc; mnv_chacha20_init(&cc, k_enc, nonce, 0);
    mnv_chacha20_decrypt(&cc, pt, ct, PT_LEN);          /* XOR == encrypt */

    mnv_crypto_header_t H0h; memcpy(H0h.iv, nonce, 12);
    H0h.weight_count = W0N+W1N+W2N; H0h.bias_count = H0+H1+OUT;
    mnv_layer_desc_t L0[3] = {
        { IN, H0,  MNV_ACT_RELU,   NULL, NULL },
        { H0, H1,  MNV_ACT_RELU,   NULL, NULL },
        { H1, OUT, MNV_ACT_LINEAR, NULL, NULL },
    };
    mnv_model_t G = { MNV_ABI_VERSION, 3, L0, &H0h, key, ct, PT_LEN };
    test_blob_mac(&G, k_mac, ct, PT_LEN, mac); memcpy(H0h.mac, mac, 32);

    static mnv_ctx_t gctx;
    CHECK(mnv_init(&gctx, &G) == MNV_OK, "genuine model must init OK");

    /* ── fuzz loop ── */
    unsigned accepted_mutations = 0;
    for (unsigned it = 0; it < FUZZ_ITERS; it++) {
        /* fresh mutable copies of everything an attacker could touch */
        uint8_t         kc[32];  memcpy(kc, key, 32);
        static uint8_t  ctc[CAP]; memcpy(ctc, ct, CAP);
        mnv_crypto_header_t Hc = H0h;
        mnv_layer_desc_t    Lc[3]; memcpy(Lc, L0, sizeof(Lc));
        mnv_model_t M = G;
        M.key = kc; M.crypto = &Hc; M.layers = Lc; M.encrypted_weights = ctc;

        switch (rr(12)) {
        case 0: M.version = (uint8_t)(MNV_ABI_VERSION ^ (1u + rr(255))); break;
        case 1: M.num_layers = (uint8_t)(1u + rr(255)); /* differs from 3 often; bound handles >3 */
                if (M.num_layers == 3) M.num_layers = 7; break;
        case 2: Lc[rr(3)].input_size  ^= (uint16_t)(1u << rr(16)); break;
        case 3: Lc[rr(3)].output_size ^= (uint16_t)(1u << rr(16)); break;
        case 4: { uint32_t li = rr(3); mnv_act_fn_t cur = Lc[li].activation, nw;
                  do { nw = (mnv_act_fn_t)rr(8); } while (nw == cur); /* real change */
                  Lc[li].activation = nw; } break;
        case 5: Hc.iv[rr(12)]  ^= (uint8_t)(1u + rr(255)); break;
        case 6: Hc.mac[rr(32)] ^= (uint8_t)(1u + rr(255)); break;
        case 7: Hc.weight_count ^= (1u << rr(32)); break;
        case 8: Hc.bias_count   ^= (1u << rr(32)); break;
        case 9: kc[rr(32)]     ^= (uint8_t)(1u + rr(255)); break;
        case 10: ctc[rr(PT_LEN)] ^= (uint8_t)(1u + rr(255)); break;
        case 11: /* length: in-range-but-different, or grossly out of range */
                 if (rr(2)) { uint32_t n; do { n = rr(CAP+1u); } while (n==PT_LEN);
                             M.encrypted_len = n; }
                 else       { M.encrypted_len = (uint32_t)MNV_MAX_WEIGHT_BYTES + 1u + rr(1000); }
                 break;
        }

        static mnv_ctx_t c;
        mnv_status_t s = mnv_init(&c, &M);   /* invariant 1: must not crash */
        /* invariant 2: a mutated model must never verify as OK */
        if (s == MNV_OK) { accepted_mutations++;
            printf("  FAIL: mutation (case seed) accepted at it=%u\n", it); fails++; }
        (void)s;
    }

    /* genuine still verifies after the storm */
    static mnv_ctx_t gctx2;
    CHECK(mnv_init(&gctx2, &G) == MNV_OK, "genuine model still OK after fuzzing");

    printf("%s (%u accepted mutations, %d failure[s])\n",
           fails ? "FAILED" : "ALL PASS", accepted_mutations, fails);
    return fails;
}
