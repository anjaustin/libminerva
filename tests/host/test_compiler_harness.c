/**
 * @file test_compiler_harness.c
 * @brief Drives a model emitted by minerva_compile.py through the real engine.
 *
 * Used by tests/host/test_compiler_emit.sh. The script generates a model with
 * the Python compiler, emits weights.c / weights.h / secrets.h next to this
 * file's include path, then compiles this harness against the engine.
 *
 * It runs a set of deterministic inputs and prints one line of decimal output
 * values per input. The script compares those lines against an INDEPENDENT
 * Python Q8 reference computed from weights_debug.npz. Any divergence between
 * the compiler's emitted model and the engine's arithmetic is thus caught.
 *
 * The deterministic input formula here MUST match the one in the Python
 * reference inside test_compiler_emit.sh.
 */

#define MNV_TARGET_HOST
#include "minerva.h"
#include "mnv_ct.h"      /* mnv_ct_argmax lives here pre-Item-3 */
#include "weights.h"     /* generated: mnv_model + topology macros */
#include <stdio.h>

#ifndef NUM_INPUTS
#define NUM_INPUTS 5
#endif

/* Deterministic input in [-40, 40]; mirrored in the Python reference. */
static int8_t gen_input(int t, int i)
{
    int v = ((t * 7 + i * 13) % 81) - 40;
    return (int8_t)v;
}

int main(void)
{
    static mnv_ctx_t ctx;
    if (mnv_init(&ctx, &mnv_model) != MNV_OK) {
        printf("INIT_FAIL\n");
        return 2;
    }

    for (int t = 0; t < NUM_INPUTS; t++) {
        int8_t in[MNV_INPUT_SIZE];
        int8_t out[MNV_OUTPUT_SIZE];
        for (int i = 0; i < (int)MNV_INPUT_SIZE; i++) in[i] = gen_input(t, i);

        if (mnv_run(&ctx, in, out) != MNV_OK) {
            printf("RUN_FAIL t=%d\n", t);
            return 3;
        }
        for (int i = 0; i < (int)MNV_OUTPUT_SIZE; i++)
            printf("%d%s", out[i], (i + 1 < (int)MNV_OUTPUT_SIZE) ? " " : "\n");
    }
    return 0;
}
