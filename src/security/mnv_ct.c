/**
 * @file mnv_ct.c
 * @brief Constant-time primitives — v1.2
 *
 * v1.2 fix: mnv_ct_argmax branchless select was broken — rewrote from scratch.
 * v1.2 fix: mnv_ct_confidence_check short-circuits to MNV_OK when
 *           MNV_MIN_CONFIDENCE == 0 (the new default).
 */

#include "mnv_ct.h"
#include <string.h>

void mnv_secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

uint8_t mnv_ct_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff;
}

void mnv_canary_plant(mnv_ctx_t *ctx)
{
    for (uint8_t i = 0; i < MNV_CANARY_COUNT; i++) {
        ctx->canary_pre[i]  = MNV_CANARY_VALUE;
        ctx->canary_post[i] = MNV_CANARY_VALUE;
    }
}

mnv_status_t mnv_canary_check(const mnv_ctx_t *ctx)
{
    uint32_t diff = 0;
    for (uint8_t i = 0; i < MNV_CANARY_COUNT; i++) {
        diff |= ctx->canary_pre[i]  ^ (uint32_t)MNV_CANARY_VALUE;
        diff |= ctx->canary_post[i] ^ (uint32_t)MNV_CANARY_VALUE;
    }
    return (diff == 0) ? MNV_OK : MNV_ERR_GLITCH;
}

/* Constant-time range check against [MNV_INPUT_MIN, MNV_INPUT_MAX]. Branchless:
 * (v - MIN) is negative (high byte 0xFF) iff v < MIN, and (MAX - v) is negative
 * iff v > MAX; either sets `bad`. NOTE the default bounds are the full Q range,
 * so for Q8 this accepts every int8 (a no-op) — see MNV_INPUT_MIN/MAX in
 * mnv_types.h for tightening it to an application-specific range. */
mnv_status_t mnv_ct_validate_input(const mnv_act_t *input, uint16_t len)
{
    uint8_t bad = 0;
    for (uint16_t i = 0; i < len; i++) {
        int16_t v = (int16_t)(int8_t)input[i];
        bad |= (uint8_t)(((uint16_t)(v - (int16_t)MNV_INPUT_MIN)) >> 8U);
        bad |= (uint8_t)(((uint16_t)((int16_t)MNV_INPUT_MAX - v)) >> 8U);
    }
    return (bad == 0) ? MNV_OK : MNV_ERR_INPUT;
}

/**
 * Constant-time argmax for int8 vector. is_gt = mnv_ct_gt_mask(vec[i]-max_val)
 * is 0xFF when vec[i] > max_val (branchless); the masked selects update the
 * running max and its index without leaking which element won. Ties keep the
 * lower index (strict >).
 */
uint8_t mnv_ct_argmax(const mnv_act_t *vec, uint16_t len)
{
    int8_t  max_val = (int8_t)vec[0];
    uint8_t max_idx = 0U;

    for (uint16_t i = 1U; i < len; i++) {
        int16_t diff16 = (int16_t)(int8_t)vec[i] - (int16_t)max_val;
        uint8_t is_gt  = mnv_ct_gt_mask(diff16);

        max_val = (int8_t) (((uint8_t)max_val         & ~is_gt) |
                             ((uint8_t)(int8_t)vec[i]  &  is_gt));
        max_idx = (uint8_t)((max_idx                  & ~is_gt) |
                             ((uint8_t)i               &  is_gt));
    }
    return max_idx;
}

mnv_status_t mnv_ct_confidence_check(const mnv_act_t *output, uint16_t len)
{
#if !defined(MNV_ENABLE_CONFIDENCE_CHECK) || (MNV_MIN_CONFIDENCE == 0)
    /* Disabled (default): threshold 0 accepts everything, including an
     * all-negative output vector. */
    (void)output; (void)len;
    return MNV_OK;
#else
    int8_t max_val = (int8_t)output[0];
    for (uint16_t i = 1U; i < len; i++) {
        int16_t d  = (int16_t)(int8_t)output[i] - (int16_t)max_val;
        uint8_t gt = mnv_ct_gt_mask(d);
        max_val = (int8_t)(((uint8_t)max_val          & ~gt) |
                            ((uint8_t)(int8_t)output[i] &  gt));
    }
    /* SIGNED comparison: logits are int8 [-128,127]. Casting max_val to
     * unsigned (the old bug) made a negative max read as ~255 and pass any
     * threshold. A negative max logit is low confidence, so reject it. */
    return ((int16_t)max_val >= (int16_t)MNV_MIN_CONFIDENCE) ? MNV_OK
                                                             : MNV_ERR_CONFIDENCE;
#endif
}
