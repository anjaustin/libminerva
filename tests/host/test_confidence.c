/**
 * @file test_confidence.c
 * @brief Confidence-check threshold semantics (host).
 *
 * Compiled with a non-zero MNV_MIN_CONFIDENCE so the threshold path is live
 * (the default 0 short-circuits to "accept"). The key regression: a negative
 * maximum logit must read as LOW confidence, not high (the old code cast the
 * signed max to unsigned, so -1 became 255 and passed any threshold).
 *
 * Build: see tests/host/run_engine_tests.sh.
 */

#define MNV_TARGET_HOST
#include "mnv_config.h"
#include "mnv_types.h"
#include "mnv_ct.h"
#include <stdio.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    printf("  %-52s %s\n", (msg), (cond) ? "PASS" : "FAIL"); \
    if (!(cond)) fails++; } while (0)

int main(void) {
    printf("[confidence-check, MNV_MIN_CONFIDENCE=%d]\n", (int)MNV_MIN_CONFIDENCE);

    mnv_act_t hi[4]  = { 50, -10, 20, -5 };   /* max 50  >= 20 */
    mnv_act_t lo[4]  = {  5, -10,  8, -5 };   /* max 8   <  20 */
    mnv_act_t neg[4] = { -1, -30, -2, -5 };   /* max -1: old bug -> 255 -> OK */

    CHECK(mnv_ct_confidence_check(hi, 4)  == MNV_OK,
          "max 50 >= threshold -> OK");
    CHECK(mnv_ct_confidence_check(lo, 4)  == MNV_ERR_CONFIDENCE,
          "max 8 < threshold -> CONFIDENCE");
    CHECK(mnv_ct_confidence_check(neg, 4) == MNV_ERR_CONFIDENCE,
          "negative max -> CONFIDENCE (regression: was OK)");

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
