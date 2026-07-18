/**
 * @file test_ct_timing.c
 * @brief dudect-style timing-leakage test for mnv_ct_compare (Law II, H2).
 *
 * Measures whether execution time depends on the DATA for the constant-time
 * comparison, using a Welch's t-test between two input classes:
 *   class 0: the two buffers are EQUAL
 *   class 1: the two buffers DIFFER in the first byte
 * A naive early-exit compare returns almost immediately on class 1 and scans
 * the whole buffer on class 0 → large timing difference (leak). mnv_ct_compare
 * OR-accumulates over the whole buffer either way → no data-dependent timing.
 *
 * Self-validating: a deliberately leaky reference (leaky_cmp) is measured on
 * the SAME classes and MUST show a large |t| (proves the harness can detect a
 * leak on this machine). If it can't — a host too noisy to measure — the test
 * SKIPS rather than giving a vacuous pass or a flaky fail. mnv_ct_compare must
 * then show |t| far below the leaky reference and below the dudect threshold.
 *
 * IMPORTANT: this tests TIMING only. It says nothing about power/EM leakage
 * (e.g. the activation-LUT address channel), which a host cannot observe — that
 * needs an oscilloscope. See the README verification-status notes.
 */
#define MNV_TARGET_HOST
#include "minerva.h"
#include "mnv_ct.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#define BUFLEN   4096
#define BATCH    256      /* compares timed per sample (amortize clock cost) */
#define SAMPLES  4000     /* samples per class */
#define T_THRESH 4.5      /* dudect leak threshold on |t|                    */

static volatile uint8_t g_sink;

/* Leaky reference: early-exit compare (like memcmp). */
static uint8_t leaky_cmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (a[i] != b[i]) return 1u;
    return 0u;
}

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* Welch's t between two arrays. */
static double welch_t(const double *x0, int n0, const double *x1, int n1)
{
    double m0 = 0, m1 = 0;
    for (int i = 0; i < n0; i++) m0 += x0[i]; m0 /= n0;
    for (int i = 0; i < n1; i++) m1 += x1[i]; m1 /= n1;
    double v0 = 0, v1 = 0;
    for (int i = 0; i < n0; i++) v0 += (x0[i]-m0)*(x0[i]-m0); v0 /= (n0-1);
    for (int i = 0; i < n1; i++) v1 += (x1[i]-m1)*(x1[i]-m1); v1 /= (n1-1);
    double denom = sqrt(v0/n0 + v1/n1);
    return denom > 0 ? (m0 - m1) / denom : 0.0;
}

typedef uint8_t (*cmp_fn)(const uint8_t*, const uint8_t*, size_t);

/* Fill timing samples for a compare fn on the two classes. */
static double measure_t(cmp_fn fn, const uint8_t *eq_a, const uint8_t *eq_b,
                        const uint8_t *df_a, const uint8_t *df_b,
                        double *s0, double *s1)
{
    for (int s = 0; s < SAMPLES; s++) {
        /* interleave classes so slow drift hits both equally */
        double t0 = now_ns();
        for (int k = 0; k < BATCH; k++) g_sink ^= fn(eq_a, eq_b, BUFLEN);
        double t1 = now_ns();
        for (int k = 0; k < BATCH; k++) g_sink ^= fn(df_a, df_b, BUFLEN);
        double t2 = now_ns();
        s0[s] = t1 - t0;   /* equal   */
        s1[s] = t2 - t1;   /* differ  */
    }
    return welch_t(s0, SAMPLES, s1, SAMPLES);
}

int main(void)
{
    printf("[ct timing: mnv_ct_compare vs leaky early-exit, %d B buffers]\n", BUFLEN);
    static uint8_t eq_a[BUFLEN], eq_b[BUFLEN], df_a[BUFLEN], df_b[BUFLEN];
    memset(eq_a, 0xA5, BUFLEN); memset(eq_b, 0xA5, BUFLEN);       /* equal  */
    memset(df_a, 0xA5, BUFLEN); memset(df_b, 0xA5, BUFLEN); df_b[0] ^= 0xFF; /* differ@0 */

    static double s0[SAMPLES], s1[SAMPLES];

    double t_leaky = fabs(measure_t(leaky_cmp, eq_a, eq_b, df_a, df_b, s0, s1));
    double t_ct    = fabs(measure_t(mnv_ct_compare, eq_a, eq_b, df_a, df_b, s0, s1));

    printf("  leaky early-exit  |t| = %8.2f  (must be >> threshold to detect leaks)\n", t_leaky);
    printf("  mnv_ct_compare    |t| = %8.2f  (threshold %.1f)\n", t_ct, T_THRESH);

    if (t_leaky < 10.0) {
        printf("  SKIP: host too noisy to detect even the leaky reference (|t|=%.2f)\n", t_leaky);
        return 0;   /* can't measure here — don't fail */
    }
    int fails = 0;
    if (!(t_leaky > T_THRESH)) { printf("  FAIL: harness did not detect the known leak\n"); fails++; }
    /* constant-time compare must be BOTH under the dudect threshold AND far
     * below the leaky reference (robust to residual host noise). */
    if (!(t_ct < T_THRESH && t_ct < t_leaky / 5.0)) {
        printf("  FAIL: mnv_ct_compare shows data-dependent timing\n"); fails++;
    } else {
        printf("  PASS: no data-dependent timing in mnv_ct_compare\n");
    }
    printf("%s\n", fails ? "CT TIMING FAILED" : "CT TIMING PASSED");
    return fails;
}
