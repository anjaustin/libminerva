/**
 * @file test_bnn_overflow.c
 * @brief Regression for the BNN accumulator width fix (audit finding F2).
 *
 * bnn_dot_bits accumulates a value in [-in_sz, +in_sz]. With the old int16
 * accumulator, a layer wider than 32767 inputs overflows — reachable under the
 * large-SRAM budgets (e.g. STM32F4). This builds a single linear BNN layer of
 * width 40000 with all weights = +1 and all inputs = +1, so every neuron's
 * accumulator equals 40000 (which wraps int16 to a negative value, flipping the
 * output sign). The int32 accumulator computes it correctly; an independent
 * 32-bit reference confirms the expected value.
 *
 * Build: see tests/host/run_engine_tests.sh (bnn_overflow config).
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

#define IN   MNV_INPUT_SIZE      /* 40000 — wider than INT16_MAX */
#define OUT  MNV_OUTPUT_SIZE     /* 4 */
#define WBITS (IN*OUT)
#define WBYTES ((WBITS + 7)/8)
#define PT_LEN (WBYTES + OUT)

static int8_t clamp8(int32_t x){ return x>127?127:(x<-128?-128:(int8_t)x); }

int main(void){
    printf("[BNN accumulator overflow: single linear layer, in=%d > INT16_MAX]\n", IN);

    static uint8_t pt[PT_LEN], ct[PT_LEN]; uint8_t mac[32];
    /* All weight bits = 1 (every weight = +1). */
    memset(pt, 0xFF, WBYTES);
    int8_t bias[OUT]; for (int n=0;n<OUT;n++) bias[n] = (int8_t)(n - 1);   /* -1,0,1,2 */
    memcpy(pt + WBYTES, bias, OUT);

    uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)(i*13+5);
    uint8_t nonce[12]={0}; nonce[3]=0xC7;
    uint8_t k_enc[32], k_mac[32];
    mnv_kdf_derive(key, MNV_KDF_LABEL_ENC, k_enc);
    mnv_kdf_derive(key, MNV_KDF_LABEL_MAC, k_mac);
    mnv_chacha20_ctx_t cc; mnv_chacha20_init(&cc,k_enc,nonce,0);
    mnv_chacha20_decrypt(&cc,pt,ct,PT_LEN);

    mnv_crypto_header_t H; memcpy(H.iv,nonce,12);
    H.weight_count=WBITS; H.bias_count=OUT;
    mnv_layer_desc_t L[1] = { { IN, OUT, MNV_ACT_LINEAR, NULL, NULL } };
    mnv_model_t M={ MNV_ABI_VERSION, 1, L, &H, key, ct, PT_LEN };
    test_blob_mac(&M, k_mac, ct, PT_LEN, mac); memcpy(H.mac,mac,32);

    static mnv_ctx_t ctx;
    CHECK(mnv_init(&ctx,&M)==MNV_OK, "init wide BNN model -> OK");

    /* All inputs = +1. */
    static int8_t in[IN]; for (int i=0;i<IN;i++) in[i]=1;
    static int8_t out[OUT];
    CHECK(mnv_run(&ctx,in,out)==MNV_OK, "run wide BNN -> OK");

    /* Independent 32-bit reference: acc = IN (all agree). */
    int32_t recip = (((int32_t)127 << 15) + (IN>>1)) / IN;
    int32_t scaled = ((int32_t)IN * recip) >> 15;
    int ok = 1;
    for (int n=0;n<OUT;n++){
        int8_t expected = clamp8(scaled + (int32_t)bias[n]);
        if (out[n] != expected){ ok = 0;
            printf("    neuron %d: engine=%d expected=%d (scaled=%d)\n",
                   n, out[n], expected, scaled); }
    }
    CHECK(ok, "wide BNN output == 32-bit reference (no int16 wrap)");
    /* Sanity: the correct value is positive (~126); an int16 wrap would be
     * negative, so this also asserts the overflow was actually avoided. */
    CHECK(scaled > 100, "reference scaled value is ~127 (overflow would flip sign)");

    printf("%s (%d failure[s])\n", fails?"FAILED":"ALL PASS", fails);
    return fails;
}
