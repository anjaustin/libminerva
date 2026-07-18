/**
 * @file test_q15_outauth.c
 * @brief Q15 output-MAC byte-coverage regression (Item 5).
 *
 * Under Q15, mnv_act_t is 2 bytes. The output authentication buffer used to be
 * sized/copied by ELEMENT count, so the MAC only covered the low half of the
 * output and input vectors — the upper byte of every element could be tampered
 * with no change to the MAC. This test builds a MAC over a Q15 output/input,
 * then flips a byte in the UPPER half of the vectors and asserts the tamper is
 * detected. Pre-fix, those cases verify as OK (the bug); post-fix they are
 * rejected.
 *
 * Built Q15 (see run_engine_tests.sh) against only the outauth + crypto
 * sources — it exercises the MAC coverage, not a full Q15 forward pass.
 */
#define MNV_TARGET_HOST
#include "minerva.h"
#include "mnv_outauth.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    int _ok = (cond); \
    printf("  %-52s %s\n", (msg), _ok ? "PASS" : "FAIL"); \
    if (!_ok) fails++; } while (0)

int main(void)
{
    printf("[q15 outauth in=%d out=%d, sizeof(act)=%zu]\n",
           (int)MNV_INPUT_SIZE, (int)MNV_OUTPUT_SIZE, sizeof(mnv_act_t));
    CHECK(sizeof(mnv_act_t) == 2, "Q15 mnv_act_t is 2 bytes");

    static mnv_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.initialized = true;
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 5 + 3);

    /* Values chosen so every element has a NON-zero high byte, so flipping the
     * high byte is a real change. */
    mnv_act_t out[MNV_OUTPUT_SIZE], in[MNV_INPUT_SIZE];
    for (int i = 0; i < (int)MNV_OUTPUT_SIZE; i++) out[i] = (mnv_act_t)(1000 + i * 300);
    for (int i = 0; i < (int)MNV_INPUT_SIZE;  i++) in[i]  = (mnv_act_t)(-900 + i * 250);

    ctx.inference_counter = 7U;                 /* compute uses 7, then -> 8 */
    mnv_outauth_compute(&ctx, key, out, in);    /* fills ctx.output_mac      */

    /* mnv_outauth_verify() takes (ctx, key, output, input) — the internal
     * order. (The public mnv_verify_output_with_key wrapper lives in the
     * engine TU, which this focused test intentionally does not link.) */

    /* Clean verify round-trips. */
    CHECK(mnv_outauth_verify(&ctx, key, out, in) == MNV_OK,
          "clean Q15 output verifies -> OK");

    /* Tamper the UPPER byte of the LAST output element (outside the pre-fix
     * coverage). Must be detected. */
    {
        mnv_act_t bad[MNV_OUTPUT_SIZE];
        memcpy(bad, out, sizeof(bad));
        bad[MNV_OUTPUT_SIZE - 1] = (mnv_act_t)(bad[MNV_OUTPUT_SIZE - 1] ^ 0x0100);
        CHECK(mnv_outauth_verify(&ctx, key, bad, in) == MNV_ERR_TAMPER,
              "tamper high byte of last output elem -> TAMPER");
    }

    /* Tamper the UPPER byte of the LAST input element. Must be detected. */
    {
        mnv_act_t bad_in[MNV_INPUT_SIZE];
        memcpy(bad_in, in, sizeof(bad_in));
        bad_in[MNV_INPUT_SIZE - 1] = (mnv_act_t)(bad_in[MNV_INPUT_SIZE - 1] ^ 0x0100);
        CHECK(mnv_outauth_verify(&ctx, key, out, bad_in) == MNV_ERR_TAMPER,
              "tamper high byte of last input elem -> TAMPER");
    }

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
