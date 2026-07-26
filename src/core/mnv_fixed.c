/**
 * @file mnv_fixed.c
 * @brief Q8 fixed-point arithmetic primitives — v1.2
 *
 * v1.2 fix: mnv_acc_t is now int32_t (was int16_t in v1.0/v1.1).
 *
 * Overflow analysis for Q8 dot product:
 *   Each term: int8 * int8 <= 127 * 127 = 16,129
 *   Max layer width: MNV_LAYER_0_SIZE = 32 (ATmega328P config)
 *   Max accumulator: 32 * 16,129 = 516,128 << INT32_MAX (2,147,483,647)
 *   INT16_MAX = 32,767 was insufficient for any layer with >= 3 inputs.
 *
 * AVR cost of int32_t arithmetic:
 *   mul (8x8->16): 2 cycles
 *   extend to 32-bit + accumulate with carry chain: ~8 cycles total
 *   vs int16 MAC: ~4 cycles
 *   Delta per inference on 8->16->8->4 model: ~18 us at 16 MHz. Acceptable.
 *
 * Shift for add_bias_clamp:
 *   acc is sum of (int8 * int8) products = Q(7+7) = Q14 scale
 *   >>7 converts to Q7, matching the int8 bias and output range [-128,127]
 */

#include "mnv_config.h"
#include "mnv_types.h"
#include "mnv_fixed.h"
#include "mnv_lut.h"   /* canonical mnv_sigmoid_lut / mnv_tanh_lut (defined in mnv_lut.c) */

/* =========================================================================
 * CONSTANT-TIME CLAMP
 * Branchless clamp of int32_t accumulator to int8_t range [-128, 127].
 * ========================================================================= */

mnv_act_t mnv_q8_clamp(mnv_acc_t x)
{
    /* Branchless clamp to [-128, 127]. No data-dependent branch, so timing and
     * power are independent of x (Law II). This matters most on AVR, which has
     * NO conditional-move instruction — the previous `if` form compiled to real
     * branches there, contradicting the constant-time claim.
     *
     * Precondition: x is a bounded inference accumulator. The widest supported
     * layer keeps |acc >> 7| well under ~2e5, far inside int32, so the
     * compare-by-subtraction below cannot overflow. */
    int32_t v  = (int32_t)x;
    int32_t hi = (127 - v) >> 31;              /* all-ones iff v > 127   */
    v = (v & ~hi) | (127 & hi);                /* v = min(v, 127)        */
    int32_t lo = (v + 128) >> 31;              /* all-ones iff v < -128  */
    v = (v & ~lo) | ((int32_t)(-128) & lo);    /* v = max(v, -128)       */
    return (mnv_act_t)v;
}

mnv_act_t mnv_q8_mul(mnv_act_t a, mnv_act_t b)
{
    mnv_acc_t product = (mnv_acc_t)((int32_t)a * (int32_t)b);
    return mnv_q8_clamp(product >> 7);
}

/**
 * @brief Q8 dot product with int32_t accumulator.
 *
 * Each weight and input is int8. The product is int16, extended to int32
 * before accumulation. No overflow possible for any layer width up to
 * MNV_MAX_SRAM_BUDGET / sizeof(int8_t) = 960 inputs:
 *   960 * 127 * 127 = 15,482,880 << INT32_MAX
 */
mnv_acc_t mnv_q8_dot(const mnv_weight_t *weights,
                     const mnv_act_t    *inputs,
                     uint16_t            len)
{
    mnv_acc_t acc = 0;
    for (uint16_t i = 0; i < len; i++) {
        acc += (mnv_acc_t)((int32_t)(int8_t)weights[i] *
                           (int32_t)(int8_t)inputs[i]);
    }
    return acc;
}

/**
 * @brief Scale Q14 accumulator to Q7, add Q7 bias, clamp to Q8.
 *
 * acc is in Q14 (product of two Q7 values, summed).
 * >>7 converts to Q7, which matches bias scale and output range.
 */
/* acc>>7 is C arithmetic right shift on int32_t: equivalent to floor(acc/128).
 * Python equivalent: acc // 128  (NOT acc >> 7 which behaves differently
 * on Python's arbitrary-precision integers). Use // 128 in validation scripts. */
mnv_act_t mnv_q8_add_bias_clamp(mnv_acc_t acc, mnv_bias_t bias)
{
    mnv_acc_t scaled = acc >> 7;
    mnv_acc_t biased = scaled + (mnv_acc_t)(int8_t)bias;
    return mnv_q8_clamp(biased);
}

/* =========================================================================
 * ACTIVATION FUNCTIONS
 * ReLU/sign are branchless arithmetic. sigmoid/tanh use the canonical LUTs
 * defined ONCE in mnv_lut.c (shared via mnv_lut.h) — read with pgm_read_byte,
 * which is a plain dereference on non-AVR targets. The blinded versions in
 * mnv_lut.c supersede these for the default Law II path; test_host.c asserts
 * these plain versions equal the blinded ones over all x.
 * ========================================================================= */

mnv_act_t mnv_act_relu(mnv_act_t x)
{
    int8_t mask = (int8_t)((int8_t)x >> 7);
    return (mnv_act_t)(x & ~mask);
}

mnv_act_t mnv_act_sigmoid(mnv_act_t x)
{
    uint8_t idx = (uint8_t)((int16_t)x + 128);
    return (mnv_act_t)pgm_read_byte(&mnv_sigmoid_lut[idx]);
}

mnv_act_t mnv_act_tanh(mnv_act_t x)
{
    uint8_t idx = (uint8_t)((int16_t)x + 128);
    return (mnv_act_t)pgm_read_byte(&mnv_tanh_lut[idx]);
}

mnv_act_t mnv_act_sign(mnv_act_t x)
{
    int8_t mask = (int8_t)((int8_t)x >> 7);
    return (mnv_act_t)((127 & ~mask) | (-128 & mask));
}

mnv_act_t mnv_apply_activation(mnv_act_fn_t fn, mnv_act_t x)
{
    switch (fn) {
        case MNV_ACT_RELU:    return mnv_act_relu(x);
        case MNV_ACT_SIGMOID: return mnv_act_sigmoid(x);
        case MNV_ACT_TANH:    return mnv_act_tanh(x);
        case MNV_ACT_SIGN:    return mnv_act_sign(x);
        case MNV_ACT_LINEAR:
        default:              return x;
    }
}
