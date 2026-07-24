/**
 * @file test_lut_uniform.c
 * @brief Blinded-LUT trace-uniformity regression (Item 8).
 *
 * The blinded activation path must look the same on a power/timing side
 * channel for EVERY activation, including the linear output layer. sigmoid,
 * tanh and relu each run a 256-entry masked scan; linear used to return x with
 * no scan, making the output layer distinguishable (Law II).
 *
 * We can't measure power in a unit test, but every scan draws exactly one PRNG
 * mask, so "a scan ran" is observable as "the PRNG advanced". This test checks
 * that the linear/default path now advances the PRNG by the SAME amount as the
 * real lookups (one step) while still returning x unchanged. Pre-fix the linear
 * path left the PRNG untouched.
 */
#ifndef MNV_TARGET_HOST      /* may be passed via -D */
#define MNV_TARGET_HOST
#endif
#include "minerva.h"
#include "mnv_lut.h"
#include "mnv_prng.h"
#include <stdio.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    int _ok = (cond); \
    printf("  %-56s %s\n", (msg), _ok ? "PASS" : "FAIL"); \
    if (!_ok) fails++; } while (0)

/* PRNG state after one mnv_prng_mask8() draw from `seed`. */
static uint32_t after_one_draw(uint32_t seed)
{
    uint32_t s = seed;
    (void)mnv_prng_mask8(&s);
    return s;
}

static uint32_t apply_and_report(mnv_act_fn_t fn, int8_t x, int8_t *out)
{
    uint32_t s = 0x12345678u;
    *out = mnv_lut_apply_blinded(fn, x, &s);
    return s;   /* PRNG state afterwards */
}

int main(void)
{
    printf("[blinded-LUT uniformity]\n");
    uint32_t one = after_one_draw(0x12345678u);
    int8_t r;

    uint32_t s_relu = apply_and_report(MNV_ACT_RELU,    50, &r);
    CHECK(s_relu == one, "relu advances PRNG by one scan");

    uint32_t s_sig  = apply_and_report(MNV_ACT_SIGMOID, 50, &r);
    CHECK(s_sig  == one, "sigmoid advances PRNG by one scan");

    uint32_t s_tanh = apply_and_report(MNV_ACT_TANH,    50, &r);
    CHECK(s_tanh == one, "tanh advances PRNG by one scan");

    /* The fix: linear (output layer) now runs the equalizing scan too. */
    int8_t lin_out;
    uint32_t s_lin = apply_and_report(MNV_ACT_LINEAR, 77, &lin_out);
    CHECK(s_lin == one, "linear advances PRNG by one scan (was: no scan)");
    CHECK(lin_out == 77, "linear still returns x unchanged");

    /* All four activations leave the PRNG in the SAME state => identical number
     * of mask draws => no per-activation distinguisher from the draw count. */
    CHECK(s_relu == s_sig && s_sig == s_tanh && s_tanh == s_lin,
          "all activations draw the same PRNG amount");

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
