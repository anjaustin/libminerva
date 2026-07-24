/**
 * @file selftest.c
 * @brief On-target self-test scaffold for the AVR PROGMEM metadata fix (H3).
 *
 * *** UNTESTED IN THE FIX ENVIRONMENT — requires avr-gcc + hardware/simavr. ***
 *
 * This is the on-target counterpart to the host access-pattern locks
 * (test_progmem_split.c / check_progmem_placement.sh). It builds a small model
 * in RAM at boot (so no generated weights.c is needed), encrypts it, then runs
 * the FULL engine pipeline — mnv_init (MAC over the PROGMEM... see note),
 * mnv_run, mnv_verify — and compares the output to an independent integer
 * reference. On real AVR this is what actually exercises:
 *   - reading the crypto header / layer descriptors from RAM (the fix), and
 *   - the weight-blob MAC/decrypt via pgm_read.
 * If any of those regressed, the MAC check or the reference comparison fails.
 *
 * NOTE: this self-test builds the ciphertext into a RAM buffer, so on AVR the
 * blob is NOT in PROGMEM here — it exercises the descriptor/crypto-header RAM
 * reads and the engine arithmetic end to end, but not the pgm_read blob path.
 * To exercise the PROGMEM blob path too, compile a real model with
 * `minerva_compile.py --target atmega328p` and run the atmega328p_classify
 * example; the host test_progmem_split.c already locks the pgm_read blob path.
 *
 * Result signalling (no UART dependency):
 *   PASS -> PB5 (Arduino D13) steady on, plus `selftest_result = 0xA5`
 *   FAIL -> PB5 fast blink,        plus `selftest_result = 0x5A`
 * A simavr harness can read `selftest_result`; a human can watch D13.
 *
 * Build: see the Makefile in this directory (avr-gcc -mmcu=atmega328p).
 */
#include <avr/io.h>
#include <util/delay.h>

#include "minerva.h"
#include "mnv_chacha20.h"
#include "mnv_blake2s.h"
#include "mnv_kdf.h"
#include "mnv_ct.h"

/* Small model: 8 -> 8 -> 8 -> 4, Q8 MLP. */
#define IN 8
#define H0 8
#define H1 8
#define OUT 4
#define W0N (H0*IN)
#define W1N (H1*H0)
#define W2N (OUT*H1)
#define PT_LEN (W0N+H0 + W1N+H1 + W2N+OUT)

volatile uint8_t selftest_result = 0x00;   /* readable by a simavr harness */

static int8_t clamp8(int32_t x){ return x>127?127:(x<-128?-128:(int8_t)x); }
static void ref_layer(const int8_t *W,const int8_t *b,const int8_t *x,int8_t *y,int in,int out,int relu){
    for(int n=0;n<out;n++){ int32_t a=0; for(int i=0;i<in;i++) a+=(int32_t)W[n*in+i]*(int32_t)x[i];
        int8_t v=clamp8((a>>7)+(int32_t)b[n]); y[n]=relu?(v<0?0:v):v; }
}

int main(void)
{
    DDRB |= (1<<PB5);   /* D13 output */

    static int8_t W0[W0N],b0[H0],W1[W1N],b1[H1],W2[W2N],b2[OUT];
    for(int i=0;i<W0N;i++) W0[i]=(int8_t)((i%5)-2);
    for(int i=0;i<H0;i++)  b0[i]=(int8_t)((i%3)-1);
    for(int i=0;i<W1N;i++) W1[i]=(int8_t)((i%3)-1);
    for(int i=0;i<W2N;i++) W2[i]=(int8_t)((i%4)-1);

    uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)(i*7+2);
    uint8_t nonce[12]={0}; nonce[0]=0x5A;
    static uint8_t pt[PT_LEN], ct[PT_LEN]; uint8_t mac[32];
    int o=0;
    for(int i=0;i<W0N;i++) pt[o++]=(uint8_t)W0[i]; for(int i=0;i<H0;i++) pt[o++]=(uint8_t)b0[i];
    for(int i=0;i<W1N;i++) pt[o++]=(uint8_t)W1[i]; for(int i=0;i<H1;i++) pt[o++]=(uint8_t)b1[i];
    for(int i=0;i<W2N;i++) pt[o++]=(uint8_t)W2[i]; for(int i=0;i<OUT;i++) pt[o++]=(uint8_t)b2[i];

    uint8_t k_enc[32], k_mac[32];
    mnv_kdf_derive(key, MNV_KDF_LABEL_ENC, k_enc);   /* domain separation (mnv_kdf.h) */
    mnv_kdf_derive(key, MNV_KDF_LABEL_MAC, k_mac);
    mnv_chacha20_ctx_t cc; mnv_chacha20_init(&cc,k_enc,nonce,0);
    mnv_chacha20_decrypt(&cc,pt,ct,PT_LEN);
    mnv_blake2s_mac(k_mac,32,ct,PT_LEN,mac);

    mnv_crypto_header_t H;
    for(int i=0;i<12;i++) H.iv[i]=nonce[i];
    for(int i=0;i<32;i++) H.mac[i]=mac[i];
    H.weight_count=W0N+W1N+W2N; H.bias_count=H0+H1+OUT;
    mnv_layer_desc_t L[3]={
        { IN,H0,MNV_ACT_RELU,  0,0 },
        { H0,H1,MNV_ACT_RELU,  0,0 },
        { H1,OUT,MNV_ACT_LINEAR,0,0 },
    };
    mnv_model_t M={ MNV_ABI_VERSION, 3, L, &H, key, ct, PT_LEN };

    static mnv_ctx_t ctx;
    uint8_t ok = 1;
    if (mnv_init(&ctx,&M) != MNV_OK) ok = 0;

    if (ok) {
        int8_t in[IN], out[OUT], h0[H0], h1[H1], ref[OUT];
        for(int i=0;i<IN;i++) in[i]=(int8_t)(i-3);
        if (mnv_run(&ctx,in,out) != MNV_OK) ok = 0;
        /* independent reference */
        ref_layer(W0,b0,in,h0,IN,H0,1);
        ref_layer(W1,b1,h0,h1,H0,H1,1);
        ref_layer(W2,b2,h1,ref,H1,OUT,0);
        for(int i=0;i<OUT;i++) if(out[i]!=ref[i]) ok=0;
        if (mnv_verify(&ctx,&M) != MNV_OK) ok = 0;
    }

    selftest_result = ok ? 0xA5 : 0x5A;

    for(;;){
        if (ok){ PORTB |= (1<<PB5); }                 /* steady on  = PASS */
        else   { PORTB ^= (1<<PB5); _delay_ms(100); } /* fast blink = FAIL */
    }
}
