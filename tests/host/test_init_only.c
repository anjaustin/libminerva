/**
 * @file test_init_only.c
 * @brief Minimal harness: compile a generated weights.c against the engine and
 *        report whether mnv_init() accepts the model. Used by test_sparity_fuzz.sh
 *        to check engine<->compiler structural-preamble (S) agreement across many
 *        random topologies — if S diverged for a shape, mnv_init returns TAMPER.
 *        Prints the numeric mnv_status_t and exits 0 iff MNV_OK.
 */
#ifndef MNV_TARGET_HOST
#define MNV_TARGET_HOST
#endif
#include <stdio.h>
#include "minerva.h"
#include "weights.h"

int main(void) {
    static mnv_ctx_t ctx;
    mnv_status_t s = mnv_init(&ctx, &mnv_model);
    printf("%d\n", (int)s);
    return (s == MNV_OK) ? 0 : 1;
}
