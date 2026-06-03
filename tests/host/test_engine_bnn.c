/**
 * @file test_engine_bnn.c
 * @brief End-to-end Binary Neural Network engine test (host), reference-checked.
 *
 * Multi-layer BNN (this is what the offset-tracking fix is about). Layer input
 * widths are multiples of 8 here so this test isolates the offset/bias fix from
 * the sub-byte width handling (covered separately).
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

/* 8 ->(sign)8 ->(sign)8 ->(linear)4, all input widths multiple of 8 */
#define IN   MNV_INPUT_SIZE      /* 8 */
#define H0   MNV_LAYER_0_SIZE    /* 8 */
#define H1   MNV_LAYER_1_SIZE    /* 8 */
#define OUT  MNV_OUTPUT_SIZE     /* 4 */

#define WB(in,out)  (((in)*(out)+7)/8)   /* packed weight bytes */
#define L0W WB(IN,H0)
#define L1W WB(H0,H1)
#define L2W WB(H1,OUT)
#define PT_LEN (L0W+H0 + L1W+H1 + L2W+OUT)

/* ±1 weight signs per layer: w[n][i], n=out, i=in */
static int8_t w0[H0][IN], w1[H1][H0], w2[OUT][H1];
static int8_t bb0[H0], bb1[H1], bb2[OUT];

static uint32_t lcg = 0x99aabbu;
static int rnd(int lo,int hi){ lcg=lcg*1103515245u+12345u; return lo+(int)((lcg>>16)%(uint32_t)(hi-lo+1)); }
static int8_t pm1(void){ return (int8_t)(rnd(0,1)?1:-1); }
static int8_t clamp8(int32_t x){ return x>127?127:(x<-128?-128:(int8_t)x); }

static void fill(void){
    for(int n=0;n<H0;n++){ for(int i=0;i<IN;i++) w0[n][i]=pm1(); bb0[n]=(int8_t)rnd(-3,3);}
    for(int n=0;n<H1;n++){ for(int i=0;i<H0;i++) w1[n][i]=pm1(); bb1[n]=(int8_t)rnd(-3,3);}
    for(int n=0;n<OUT;n++){for(int i=0;i<H1;i++) w2[n][i]=pm1(); bb2[n]=(int8_t)rnd(-3,3);}
}

/* pack ±1 weights: global bit index n*in+i, byte little-endian (matches qbin) */
static void pack_w(uint8_t *dst, const int8_t *w, int in_sz, int out_sz){
    int nbits = in_sz*out_sz, nbytes = (nbits+7)/8;
    memset(dst,0,(size_t)nbytes);
    for(int n=0;n<out_sz;n++) for(int i=0;i<in_sz;i++){
        int idx=n*in_sz+i;
        if (w[n*in_sz+i] >= 0) dst[idx/8] |= (uint8_t)(1u<<(idx%8));
    }
}

/* reference: a_val = sign(src), acc=sum w_val*a_val, scaled=acc*127/in, +bias */
static int8_t ref_neuron(const int8_t *w, const int8_t *src, int in_sz, int8_t bias){
    int32_t acc=0;
    for(int i=0;i<in_sz;i++){ int a = src[i]>=0?1:-1; acc += (int)w[i]*a; }
    int32_t scaled = acc*127/in_sz;
    return clamp8(scaled + (int32_t)bias);
}
static int8_t act_sign(int8_t x){ return x>=0?127:-128; }

static void reference_forward(const int8_t *in, int8_t *out){
    int8_t a[IN], h0[H0], h1[H1];
    memcpy(a,in,IN);
    for(int n=0;n<H0;n++) h0[n]=act_sign(ref_neuron(&w0[n][0],a, IN,bb0[n]));
    for(int n=0;n<H1;n++) h1[n]=act_sign(ref_neuron(&w1[n][0],h0,H0,bb1[n]));
    for(int n=0;n<OUT;n++)out[n]=ref_neuron(&w2[n][0],h1,H1,bb2[n]);   /* linear */
}

static void serialize(uint8_t *pt){
    size_t o=0;
    pack_w(pt+o,&w0[0][0],IN,H0); o+=L0W; memcpy(pt+o,bb0,H0); o+=H0;
    pack_w(pt+o,&w1[0][0],H0,H1); o+=L1W; memcpy(pt+o,bb1,H1); o+=H1;
    pack_w(pt+o,&w2[0][0],H1,OUT);o+=L2W; memcpy(pt+o,bb2,OUT);
}

int main(void){
    printf("[engine BNN %d->%d->%d->%d (multi-layer)]\n",IN,H0,H1,OUT);
    fill();
    uint8_t key[32]; for(int i=0;i<32;i++)key[i]=(uint8_t)(i*3+9);
    uint8_t nonce[12]={0}; nonce[2]=0x77;
    static uint8_t pt[PT_LEN], ct[PT_LEN]; uint8_t mac[32];
    serialize(pt);
    mnv_chacha20_ctx_t cc; mnv_chacha20_init(&cc,key,nonce,0);
    mnv_chacha20_decrypt(&cc,pt,ct,PT_LEN);
    mnv_blake2s_mac(key,32,ct,PT_LEN,mac);

    mnv_crypto_header_t H; memcpy(H.iv,nonce,12); memcpy(H.mac,mac,32);
    H.weight_count=L0W+L1W+L2W; H.bias_count=H0+H1+OUT;
    mnv_layer_desc_t L[3]={
        { IN, H0, MNV_ACT_SIGN,   NULL,NULL },
        { H0, H1, MNV_ACT_SIGN,   NULL,NULL },
        { H1, OUT,MNV_ACT_LINEAR, NULL,NULL },
    };
    mnv_model_t M={ MNV_ABI_VERSION, 3, L, &H, key, ct, PT_LEN };

    static mnv_ctx_t ctx;
    CHECK(mnv_init(&ctx,&M)==MNV_OK, "init valid BNN model -> OK");

    int ok=1;
    for(int t=0;t<8;t++){
        int8_t in[IN], out[OUT], ref[OUT];
        /* BINARY quant: valid input range is [-1,1], so inputs are +/-1 */
        for(int i=0;i<IN;i++) in[i]=pm1();
        if (mnv_run(&ctx,in,out)!=MNV_OK){ ok=0; break; }
        reference_forward(in,ref);
        if (memcmp(out,ref,OUT)!=0){
            ok=0; printf("    mismatch t=%d engine[",t);
            for(int i=0;i<OUT;i++)printf("%d ",out[i]); printf("] ref[");
            for(int i=0;i<OUT;i++)printf("%d ",ref[i]); printf("]\n"); break;
        }
    }
    CHECK(ok, "BNN multi-layer output == independent reference (8 inputs)");

    static uint8_t ctb[PT_LEN]; memcpy(ctb,ct,PT_LEN); ctb[3]^=0x20;
    mnv_model_t Mt={ MNV_ABI_VERSION, 3, L, &H, key, ctb, PT_LEN };
    static mnv_ctx_t ctxt;
    CHECK(mnv_init(&ctxt,&Mt)==MNV_ERR_TAMPER, "init flipped ct -> TAMPER");

    printf("%s (%d failure[s])\n", fails?"FAILED":"ALL PASS", fails);
    return fails;
}
