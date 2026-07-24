/**
 * @file test_cnn_accuracy_harness.c
 * @brief Runs a compiled CNN1D model and prints the argmax per input (H4).
 *
 * Reads from stdin: a first line "N", then N lines each with MNV_INPUT_SIZE
 * space-separated integers (Q8 inputs). Prints one argmax per input. Used by
 * test_cnn_accuracy.sh to measure how well the Q8 engine's decisions match the
 * float model's, and whether --calibrate improves it.
 */
#ifndef MNV_TARGET_HOST      /* may be passed via -D */
#define MNV_TARGET_HOST
#endif
#include "minerva.h"
#include "mnv_ct.h"
#include "weights.h"
#include <stdio.h>

int main(void)
{
    static mnv_ctx_t ctx;
    if (mnv_init(&ctx, &mnv_model) != MNV_OK) { fprintf(stderr, "INIT_FAIL\n"); return 2; }

    int n = 0;
    if (scanf("%d", &n) != 1) return 3;
    for (int t = 0; t < n; t++) {
        int8_t in[MNV_INPUT_SIZE], out[MNV_OUTPUT_SIZE];
        for (int i = 0; i < (int)MNV_INPUT_SIZE; i++) { int v; if (scanf("%d", &v) != 1) return 3; in[i] = (int8_t)v; }
        if (mnv_run(&ctx, in, out) != MNV_OK) { fprintf(stderr, "RUN_FAIL %d\n", t); return 4; }
        printf("%u\n", mnv_ct_argmax(out, MNV_OUTPUT_SIZE));
    }
    return 0;
}
