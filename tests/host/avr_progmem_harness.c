/**
 * @file avr_progmem_harness.c
 * @brief Dual host/AVR harness for the compiler-emitted PROGMEM weight path.
 *
 * Runs mnv_init() + mnv_run() on a fixed input against a compiler-generated
 * model (weights.h/.c). Built TWICE by tests/host/test_avr_sim.sh:
 *   - MNV_TARGET_HOST: prints the output — the trustworthy oracle (the host
 *     engine is checked against an independent integer reference elsewhere).
 *   - ATmega328P (PROGMEM): compares the output to the oracle bytes passed via
 *     -DEXP0..3 and writes 0xA5 (PASS) / 0x5A (FAIL) to `avr_result`, which the
 *     simavr runner reads. A PASS means the real Harvard AVR flash/RAM path
 *     (pgm_read weight blob, RAM descriptors, blinded-LUT pgm_read) reproduces
 *     the host result bit-for-bit.
 */
#include "minerva.h"
#include "weights.h"
#if defined(MNV_TARGET_HOST)
#include <stdio.h>
#endif

static mnv_ctx_t ctx;
volatile uint8_t avr_result = 0;   /* read by the simavr runner (SRAM byte) */

int main(void) {
    int8_t in[MNV_INPUT_SIZE], out[MNV_OUTPUT_SIZE];
    for (int i = 0; i < MNV_INPUT_SIZE;  i++) in[i]  = (int8_t)(17 - 5 * i);
    for (int i = 0; i < MNV_OUTPUT_SIZE; i++) out[i] = 0;

    mnv_status_t s = mnv_init(&ctx, &mnv_model);
    if (s == MNV_OK) s = mnv_run(&ctx, in, out);

#if defined(MNV_TARGET_HOST)
    printf("init/run=%d out=", (int)s);
    for (int i = 0; i < MNV_OUTPUT_SIZE; i++) printf("%d ", out[i]);
    printf("\n");
    return 0;
#else
    uint8_t ok = (s == MNV_OK);
    const int8_t exp[4] = { EXP0, EXP1, EXP2, EXP3 };
    for (int i = 0; i < MNV_OUTPUT_SIZE; i++) if (out[i] != exp[i]) ok = 0;
    avr_result = ok ? 0xA5 : 0x5A;
    for (;;) { }
#endif
}
