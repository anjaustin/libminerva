/**
 * @file test_input_bounds.c
 * @brief Configurable input-range validation (audit finding F2).
 *
 * mnv_ct_validate_input() defaults to the full quantization range, so for Q8 it
 * accepts every int8 (a structural no-op — documented). This test compiles with
 * an application-tightened range (-DMNV_INPUT_MIN=-100 -DMNV_INPUT_MAX=100, see
 * run_engine_tests.sh) and proves the bound is actually enforced: in-range
 * inputs pass, out-of-range inputs (including the int8 extremes ±128/127 that
 * the DEFAULT range would accept) are rejected with MNV_ERR_INPUT. The check
 * stays branchless — this only exercises the result, not its timing.
 */
#define MNV_TARGET_HOST
#include "minerva.h"
#include "mnv_ct.h"
#include <stdio.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    int _ok = (cond); \
    printf("  %-56s %s\n", (msg), _ok ? "PASS" : "FAIL"); \
    if (!_ok) fails++; } while (0)

int main(void)
{
    printf("[input bounds: MNV_INPUT_MIN=%d MNV_INPUT_MAX=%d]\n",
           (int)MNV_INPUT_MIN, (int)MNV_INPUT_MAX);

    /* Sanity: the test is only meaningful if the range was tightened below the
     * full int8 domain (otherwise everything trivially passes). */
    CHECK(MNV_INPUT_MIN > -128 || MNV_INPUT_MAX < 127,
          "range is tightened below full int8 (else test is vacuous)");

    int8_t in_range[]   = { 0, 100, -100, 50, -50, 99, -99 };
    CHECK(mnv_ct_validate_input(in_range, (uint16_t)(sizeof in_range)) == MNV_OK,
          "all in-range values accepted");

    int8_t hi_edge[]    = { 0, 101 };            /* just above max */
    CHECK(mnv_ct_validate_input(hi_edge, 2) == MNV_ERR_INPUT,
          "value just above MNV_INPUT_MAX rejected");

    int8_t lo_edge[]    = { -101, 0 };           /* just below min */
    CHECK(mnv_ct_validate_input(lo_edge, 2) == MNV_ERR_INPUT,
          "value just below MNV_INPUT_MIN rejected");

    int8_t int8_extreme[] = { 127, -128 };       /* DEFAULT range would accept */
    CHECK(mnv_ct_validate_input(int8_extreme, 2) == MNV_ERR_INPUT,
          "int8 extremes rejected under tightened range");

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
