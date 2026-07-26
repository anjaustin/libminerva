/**
 * @file mnv_cnn1d.c
 * @brief 1D CNN forward pass — v1.3 (stress-tested, fully bug-fixed)
 *
 * Bug fixes vs original:
 *   Bug 6:  MNV_CNN_DENSE_SHIFT replaces hardcoded >>7 for dense layer
 *   Bug 7:  arch-guarded #include in mnv_engine.c (fixed there)
 *   Bug 10: ct_offset tracks ciphertext position — was always reading from
 *           offset 0 (MLP engine uses ct+ct_offset pattern correctly;
 *           CNN1D was missing it entirely)
 *
 * Weight blob layout (must match minerva_compile.py CnnCompiler exactly):
 *   [kernel_f0[0..K-1] | ... | kernel_fN[0..K-1]]   N*K bytes  (filter-major)
 *   [conv_bias[0..N-1]]                              N bytes
 *   [dense_W.T row-major]                            OUTPUT*FLAT bytes
 *   [dense_bias[0..OUTPUT-1]]                        OUTPUT bytes
 */

#include "mnv_cnn1d.h"
#include "mnv_fixed.h"
#include "mnv_ct.h"
#include "mnv_chacha20.h"
#include "mnv_lut.h"
#include <string.h>

#if defined(MNV_ARCH_CNN1D)

/* ── Derived dimensions ────────────────────────────────────────────────────── */
#define MNV_CNN_CONV_LEN   (MNV_INPUT_SIZE - MNV_CNN_KERNEL_SIZE + 1U)
#define MNV_CNN_POOL_LEN   (MNV_CNN_CONV_LEN / MNV_CNN_POOL_SIZE)
#define MNV_CNN_FLAT_SIZE  (MNV_CNN_NUM_FILTERS * MNV_CNN_POOL_LEN)

/* Compile-time shape sanity (F3). CNN1D takes its shape from the MNV_CNN_*
 * macros (num_layers == 0), so a misconfigured build has no runtime layer
 * descriptor to catch it. These make an impossible/inconsistent geometry a
 * build error instead of a silent runtime miscompute. The blob's core dims are
 * additionally bound into the integrity MAC (see mnv_struct_auth.h), so an
 * engine/compiler shape mismatch is rejected at mnv_init(). */
MNV_STATIC_ASSERT(MNV_INPUT_SIZE >= MNV_CNN_KERNEL_SIZE, cnn_kernel_wider_than_input);
MNV_STATIC_ASSERT(MNV_CNN_CONV_LEN >= MNV_CNN_POOL_SIZE, cnn_pool_wider_than_conv);
MNV_STATIC_ASSERT(MNV_CNN_POOL_LEN > 0U,                 cnn_pool_len_zero);
MNV_STATIC_ASSERT(MNV_CNN_FLAT_SIZE == MNV_CTX_BUF_SIZE, cnn_flat_vs_ctx_buf);
MNV_STATIC_ASSERT(MNV_CNN_FLAT_SIZE <= MNV_CTX_BUF_SIZE, cnn_featmap_overflows_buf);

/* Static scratch for one filter's pre-pool conv output.
 * NOTE: file-scope (not in mnv_ctx_t) -> this forward pass is single-context
 * and not reentrant. Fine for the intended one-inference-at-a-time embedded
 * use; do not call concurrently. It is wiped after each filter, not by
 * mnv_destroy(). */
static mnv_act_t conv_scratch[MNV_CNN_CONV_LEN];

/* ── Branchless max (CT): shared mnv_ct_gt_mask, was hand-inlined here ──────── */
static inline mnv_act_t ct_max8(mnv_act_t a, mnv_act_t b)
{
    int16_t  diff = (int16_t)(int8_t)b - (int16_t)(int8_t)a;
    uint8_t  b_gt = mnv_ct_gt_mask(diff);
    return (mnv_act_t)(((uint8_t)(int8_t)a & ~b_gt) |
                       ((uint8_t)(int8_t)b &  b_gt));
}

/* ── Single-filter: conv + ReLU + maxpool ──────────────────────────────────── */
static void conv1d_filter_forward(const mnv_weight_t *kernel,
                                  mnv_bias_t          bias,
                                  const mnv_act_t    *input,
                                  mnv_act_t          *pool_out,
                                  uint32_t           *prng_state)
{
    /* Convolution + ReLU */
    for (uint16_t i = 0U; i < MNV_CNN_CONV_LEN; i++) {
        mnv_acc_t acc = 0;
        for (uint16_t k = 0U; k < MNV_CNN_KERNEL_SIZE; k++) {
            acc += (mnv_acc_t)((int32_t)(int8_t)kernel[k] *
                               (int32_t)(int8_t)input[i + k]);
        }
        mnv_act_t pre = mnv_q8_add_bias_clamp(acc, bias);
#if defined(MNV_ENABLE_BLINDED_LUT)
        conv_scratch[i] = mnv_lut_apply_blinded(MNV_ACT_RELU, pre, prng_state);
#else
        conv_scratch[i] = mnv_apply_activation(MNV_ACT_RELU, pre);
        (void)prng_state;
#endif
    }

    /* MaxPool — branchless CT max */
    for (uint16_t p = 0U; p < MNV_CNN_POOL_LEN; p++) {
        mnv_act_t mv = conv_scratch[p * MNV_CNN_POOL_SIZE];
        for (uint16_t j = 1U; j < MNV_CNN_POOL_SIZE; j++)
            mv = ct_max8(mv, conv_scratch[p * MNV_CNN_POOL_SIZE + j]);
        pool_out[p] = mv;
    }
}

/* ── CNN1D forward pass ────────────────────────────────────────────────────── */
mnv_status_t mnv_cnn1d_forward(mnv_ctx_t          *ctx,
                                const mnv_model_t  *model,
                                const mnv_act_t    *input,
                                mnv_act_t          *output,
                                mnv_chacha20_ctx_t *chacha)
{
    mnv_status_t status;
    const uint8_t *ct     = model->encrypted_weights;
    uint32_t       ct_off = 0U;   /* FIX Bug 10: track ciphertext offset (uint32:
                                   * blob may exceed 64 KB on flat-memory targets) */

    mnv_act_t *feat_map = ctx->buf_a;   /* [MNV_CNN_FLAT_SIZE] */

    /* ── Conv block: all kernels first, then all biases ── */
    /* Blob layout: [K0 K1 ... KN] then [b0 b1 ... bN]        */
    /* Matches minerva_compile.py CnnCompiler: kernels flat, then biases flat */

    uint32_t kernel_bytes = (uint32_t)MNV_CNN_KERNEL_SIZE * sizeof(mnv_weight_t);
    uint32_t all_kernels  = (uint32_t)MNV_CNN_NUM_FILTERS * kernel_bytes;
    uint32_t all_biases   = (uint32_t)MNV_CNN_NUM_FILTERS * sizeof(mnv_bias_t);

    /* Decrypt all kernels into a temporary staging area. weight_scratch is
     * sized to max(F*K, FLAT) (see mnv_types.h), so it always holds all F*K
     * staged kernel bytes as well as a dense row. */
    mnv_chacha20_decrypt(chacha, ct + ct_off,
                         (uint8_t *)ctx->weight_scratch, all_kernels);
    ct_off += all_kernels;

    /* Decrypt all conv biases into a small local array */
    mnv_bias_t conv_bias[MNV_CNN_NUM_FILTERS];
    mnv_chacha20_decrypt(chacha, ct + ct_off,
                         (uint8_t *)conv_bias, all_biases);
    ct_off += all_biases;

    /* Apply each filter using its staged kernel */
    for (uint16_t f = 0U; f < MNV_CNN_NUM_FILTERS; f++) {
        conv1d_filter_forward(
            &ctx->weight_scratch[f * MNV_CNN_KERNEL_SIZE],
            conv_bias[f],
            input,
            feat_map + f * MNV_CNN_POOL_LEN,
            &ctx->prng_state);

        mnv_secure_zero(conv_scratch, sizeof(conv_scratch));

        status = mnv_canary_check(ctx);
        if (status != MNV_OK) goto fail;
    }

    mnv_secure_zero(conv_bias, sizeof(conv_bias));
    /* Wipe the full staged kernel region — all_kernels is uint32; casting to
     * uint16 (old) left decrypted kernels resident for blobs > 64 KB (Law II). */
    mnv_secure_zero(ctx->weight_scratch, all_kernels);

    /* ── Dense output layer — one row at a time ── */
    uint32_t flat_bytes = (uint32_t)MNV_CNN_FLAT_SIZE * sizeof(mnv_weight_t);

    /* Hold each output's shifted accumulator in the ACCUMULATOR domain (int32,
     * not yet clamped to int8) so the dense bias can be folded in before a
     * SINGLE clamp. The dense bias is streamed after all the weight rows, so it
     * is not available inside this loop; the old code clamped here and added
     * bias afterward, which lost precision — a value saturated at ±127 pre-bias
     * could never be pulled back into range, and the shift calibration (H4)
     * targets the pre-bias accumulator, so a large bias re-saturated the clamp. */
    mnv_acc_t dense_pre[MNV_OUTPUT_SIZE];

    for (uint16_t n = 0U; n < MNV_OUTPUT_SIZE; n++) {
        mnv_chacha20_decrypt(chacha, ct + ct_off,
                             (uint8_t *)ctx->weight_scratch, flat_bytes);
        ct_off += flat_bytes;

        mnv_acc_t acc = mnv_q8_dot(ctx->weight_scratch, feat_map,
                                    MNV_CNN_FLAT_SIZE);
        /* Dense shift: ceil(log2(FLAT_SIZE)) + 7 (or calibrated). Bias is added
         * below, in this same domain, before the clamp. */
        dense_pre[n] = acc >> MNV_CNN_DENSE_SHIFT;

        mnv_secure_zero(ctx->weight_scratch, flat_bytes);
    }

    /* Decrypt dense biases and apply them in the accumulator domain with a
     * single clamp (see dense_pre above). */
    mnv_bias_t dense_bias[MNV_OUTPUT_SIZE];
    mnv_chacha20_decrypt(chacha, ct + ct_off,
                         (uint8_t *)dense_bias,
                         (uint16_t)(MNV_OUTPUT_SIZE * sizeof(mnv_bias_t)));
    ct_off += (uint16_t)(MNV_OUTPUT_SIZE * sizeof(mnv_bias_t));
    (void)ct_off;   /* suppress unused warning */

    for (uint16_t n = 0U; n < MNV_OUTPUT_SIZE; n++)
        output[n] = mnv_q8_clamp(dense_pre[n] + (mnv_acc_t)(int8_t)dense_bias[n]);

    mnv_secure_zero(dense_pre,  sizeof(dense_pre));
    mnv_secure_zero(dense_bias, sizeof(dense_bias));

    status = mnv_canary_check(ctx);
    if (status != MNV_OK) goto fail;

    return MNV_OK;

fail:
    mnv_secure_zero(output,             MNV_ACT_BYTES(MNV_OUTPUT_SIZE));
    mnv_secure_zero(feat_map,           MNV_ACT_BYTES(MNV_CNN_FLAT_SIZE));
    mnv_secure_zero(ctx->weight_scratch, sizeof(ctx->weight_scratch));
    mnv_secure_zero(conv_scratch,        sizeof(conv_scratch));
    return MNV_ERR_GLITCH;
}

#endif /* MNV_ARCH_CNN1D */
