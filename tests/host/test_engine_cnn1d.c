/**
 * @file test_engine_cnn1d.c
 * @brief End-to-end 1D-CNN engine test (host), reference-checked.
 *
 * Mirrors the engine's conv -> ReLU -> maxpool -> dense -> shift -> bias
 * pipeline with an independent integer reference and compares outputs.
 *
 * Build: see tests/host/run_engine_tests.sh.
 */

#define MNV_TARGET_HOST
#include "minerva.h"
#include "mnv_chacha20.h"
#include "mnv_blake2s.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    printf("  %-52s %s\n", (msg), (cond) ? "PASS" : "FAIL"); \
    if (!(cond)) fails++; } while (0)

#define IN        MNV_INPUT_SIZE
#define K         MNV_CNN_KERNEL_SIZE
#define F         MNV_CNN_NUM_FILTERS
#define POOL      MNV_CNN_POOL_SIZE
#define OUT       MNV_OUTPUT_SIZE
#define SHIFT     MNV_CNN_DENSE_SHIFT
#define CONV_LEN  (IN - K + 1)
#define POOL_LEN  (CONV_LEN / POOL)
#define FLAT      (F * POOL_LEN)

/* blob: kernels[F*K] convbias[F] denseW[OUT*FLAT] densebias[OUT] */
#define PT_LEN (F*K + F + OUT*FLAT + OUT)

static int8_t kern[F*K], cbias[F], dW[OUT*FLAT], dbias[OUT];

static uint32_t lcg = 0x2244668u;
static int8_t small_rand(int lo, int hi) {
    lcg = lcg * 1103515245u + 12345u;
    int span = hi - lo + 1;
    return (int8_t)(lo + (int)((lcg >> 16) % (uint32_t)span));
}
static int8_t clamp8(int32_t x){ return x>127?127:(x<-128?-128:(int8_t)x); }

static void fill(void){
    for (int i=0;i<F*K;i++)     kern[i]  = small_rand(-3,3);
    for (int i=0;i<F;i++)       cbias[i] = small_rand(-2,2);
    for (int i=0;i<OUT*FLAT;i++)dW[i]    = small_rand(-2,2);
    for (int i=0;i<OUT;i++)     dbias[i] = small_rand(-2,2);
}

static void reference_forward(const int8_t *in, int8_t *out){
    int8_t feat[FLAT];
    for (int f=0; f<F; f++){
        int8_t conv[CONV_LEN];
        for (int i=0;i<CONV_LEN;i++){
            int32_t acc=0;
            for (int k=0;k<K;k++) acc += (int32_t)kern[f*K+k]*(int32_t)in[i+k];
            int8_t v = clamp8((acc>>7) + (int32_t)cbias[f]);
            conv[i] = v<0?0:v;                    /* ReLU */
        }
        for (int p=0;p<POOL_LEN;p++){
            int8_t mv = conv[p*POOL];
            for (int j=1;j<POOL;j++){ int8_t c=conv[p*POOL+j]; if (c>mv) mv=c; }
            feat[f*POOL_LEN+p]=mv;
        }
    }
    for (int n=0;n<OUT;n++){
        int32_t acc=0;
        for (int j=0;j<FLAT;j++) acc += (int32_t)dW[n*FLAT+j]*(int32_t)feat[j];
        int8_t v = clamp8(acc>>SHIFT);            /* engine clamps pre-bias */
        out[n] = clamp8((int32_t)v + (int32_t)dbias[n]);
    }
}

static void serialize(uint8_t *pt){
    size_t o=0;
    memcpy(pt+o,kern,F*K); o+=F*K;
    memcpy(pt+o,cbias,F);  o+=F;
    memcpy(pt+o,dW,OUT*FLAT); o+=OUT*FLAT;
    memcpy(pt+o,dbias,OUT);
}

int main(void){
    printf("[engine CNN1D in=%d K=%d F=%d pool=%d -> flat=%d -> out=%d shift=%d]\n",
           IN,K,F,POOL,FLAT,OUT,SHIFT);
    fill();

    uint8_t key[32]; for(int i=0;i<32;i++)key[i]=(uint8_t)(i*5+3);
    uint8_t nonce[12]={0}; nonce[1]=0x33;
    static uint8_t pt[PT_LEN], ct[PT_LEN]; uint8_t mac[32];
    serialize(pt);
    mnv_chacha20_ctx_t cc; mnv_chacha20_init(&cc,key,nonce,0);
    mnv_chacha20_decrypt(&cc,pt,ct,PT_LEN);
    mnv_blake2s_mac(key,32,ct,PT_LEN,mac);

    mnv_crypto_header_t H; memcpy(H.iv,nonce,12); memcpy(H.mac,mac,32);
    H.weight_count=F*K+OUT*FLAT; H.bias_count=F+OUT;
    /* CNN1D engine ignores the per-layer descriptor array (num_layers=0). */
    mnv_model_t M={ MNV_ABI_VERSION, 0, NULL, &H, key, ct, PT_LEN };

    static mnv_ctx_t ctx;
    CHECK(mnv_init(&ctx,&M)==MNV_OK, "init valid CNN1D model -> OK");

    int ok=1;
    for (int t=0;t<8;t++){
        int8_t in[IN], out[OUT], ref[OUT];
        for (int i=0;i<IN;i++) in[i]=small_rand(-50,50);
        if (mnv_run(&ctx,in,out)!=MNV_OK){ ok=0; break; }
        reference_forward(in,ref);
        if (memcmp(out,ref,OUT)!=0){
            ok=0;
            printf("    mismatch t=%d engine[",t);
            for(int i=0;i<OUT;i++)printf("%d ",out[i]);
            printf("] ref[");
            for(int i=0;i<OUT;i++)printf("%d ",ref[i]);
            printf("]\n");
            break;
        }
    }
    CHECK(ok, "CNN1D output == independent reference (8 inputs)");

    /* tamper path */
    static uint8_t ctb[PT_LEN]; memcpy(ctb,ct,PT_LEN); ctb[5]^=0x40;
    mnv_model_t Mt={ MNV_ABI_VERSION, 0, NULL, &H, key, ctb, PT_LEN };
    static mnv_ctx_t ctxt;
    CHECK(mnv_init(&ctxt,&Mt)==MNV_ERR_TAMPER, "init flipped ct -> TAMPER");

    printf("%s (%d failure[s])\n", fails?"FAILED":"ALL PASS", fails);
    return fails;
}
