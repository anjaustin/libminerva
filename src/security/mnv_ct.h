/**
 * @file mnv_ct.h
 * @brief Constant-time primitives — internal header
 */

#ifndef MNV_CT_H
#define MNV_CT_H

#include "mnv_types.h"

/**
 * @brief Constant-time "greater-than" mask.
 * @param diff  a difference of two int8 values, i.e. (b - a), range [-255,255].
 * @return 0xFF if diff > 0 (b > a), else 0x00 — with NO data-dependent branch.
 *
 * (diff - 1) >= 0 exactly when diff > 0; its int16 sign bit, read as the top
 * byte of the unsigned value after >> 8, gives an all-ones/all-zeros mask. This
 * security-critical idiom was hand-inlined in mnv_ct_argmax, the confidence
 * check, and the CNN1D maxpool; defining it once means it is audited once.
 */
static inline uint8_t mnv_ct_gt_mask(int16_t diff)
{
    return (uint8_t)(~((uint8_t)((uint16_t)((int16_t)(diff - 1)) >> 8U)));
}

void         mnv_secure_zero(void *ptr, size_t len);
uint8_t      mnv_ct_compare(const uint8_t *a, const uint8_t *b, size_t len);
void         mnv_canary_plant(mnv_ctx_t *ctx);
mnv_status_t mnv_canary_check(const mnv_ctx_t *ctx);
mnv_status_t mnv_ct_validate_input(const mnv_act_t *input, uint16_t len);
uint8_t      mnv_ct_argmax(const mnv_act_t *vec, uint16_t len);
mnv_status_t mnv_ct_confidence_check(const mnv_act_t *output, uint16_t len);

#endif /* MNV_CT_H */
