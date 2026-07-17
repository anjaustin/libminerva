/**
 * @file test_outauth_counter.c
 * @brief Output-MAC counter guard + wraparound (Item 9).
 *
 * mnv_outauth_verify() used to compute counter-1 with no "has a MAC ever been
 * produced" check. Two edge cases matter:
 *   - Before any inference: verification must fail (nothing to verify).
 *   - After exactly 2^32 inferences the counter wraps to 0; a genuine output
 *     produced then must STILL verify — (counter - 1) == 0xFFFFFFFF is the
 *     correct modular value matching the compute side. A naive "counter == 0 ->
 *     reject" gate would wrongly reject that output; the has_output_mac flag
 *     handles both cases.
 *
 * Everything is observed through mnv_outauth_verify() return values (external
 * calls that read the real ctx state), so it is not subject to the compiler
 * caching a white-box read of ctx across a call. Driven against the outauth +
 * crypto sources only.
 */
#define MNV_TARGET_HOST
#include "minerva.h"
#include "mnv_outauth.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    printf("  %-56s %s\n", (msg), (cond) ? "PASS" : "FAIL"); \
    if (!(cond)) fails++; } while (0)

int main(void)
{
    printf("[outauth counter guard]\n");
    static mnv_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.initialized = true;
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 1);

    mnv_act_t out[MNV_OUTPUT_SIZE], in[MNV_INPUT_SIZE];
    for (int i = 0; i < (int)MNV_OUTPUT_SIZE; i++) out[i] = (mnv_act_t)(i + 1);
    for (int i = 0; i < (int)MNV_INPUT_SIZE;  i++) in[i]  = (mnv_act_t)(i + 2);

    /* 1. Before any inference has produced a MAC: reject (has_output_mac). */
    CHECK(mnv_outauth_verify(&ctx, key, out, in) == MNV_ERR_TAMPER,
          "verify before any inference -> TAMPER");

    /* 2. Prime the counter to its max so this inference wraps it to 0. */
    ctx.inference_counter = 0xFFFFFFFFu;
    mnv_outauth_compute(&ctx, key, out, in);       /* counter -> 0, mac set */

    /* A genuine output produced at the wrap point must still verify. This is
     * the case a naive counter==0 gate would wrongly reject. */
    CHECK(mnv_outauth_verify(&ctx, key, out, in) == MNV_OK,
          "verify genuine output after counter wrap -> OK");

    /* 3. Integrity still holds after the wrap: a tampered output is rejected. */
    {
        mnv_act_t bad[MNV_OUTPUT_SIZE];
        memcpy(bad, out, sizeof(bad));
        bad[0] = (mnv_act_t)(bad[0] ^ 0x01);
        CHECK(mnv_outauth_verify(&ctx, key, bad, in) == MNV_ERR_TAMPER,
              "verify tampered output after wrap -> TAMPER");
    }

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
