/**
 * @file mnv_bnn.c
 * @brief Binary Neural Network (BNN) forward pass
 *
 * Weights ∈ {-1, +1}, packed 8 per byte (1 = +1, 0 = -1).
 * Activations ∈ {-1, +1} after sign activation.
 *
 * Multiply-accumulate becomes:
 *   XNOR(weight_bit, activation_bit) → popcount → scale
 *
 * This is:
 *   - ~58× fewer operations than Q8 on AVR
 *   - Inherently constant-time (popcount is data-independent in time)
 *   - Maximally compact: 8 weights per byte
 *
 * On ATtiny85 with 2KB weight budget: ~16K binary weights feasible.
 *
 * Weight packing: weights[byte] bit k = 1 → w = +1, 0 → w = -1
 * Packed column-major for XNOR efficiency.
 *
 * Stream layout per layer (matches the compiler): [packed weights][int8
 * biases]. The popcount result is scaled to Q8 and the (int8) bias is added
 * before the activation. The ciphertext offset is tracked across layers so
 * each layer decrypts the correct bytes.
 */

#include "mnv_bnn.h"
#include "../core/mnv_fixed.h"
#include "../security/mnv_ct.h"
#include "../security/mnv_chacha20.h"
#include <string.h>

#if defined(MNV_ARCH_BNN)

/* Fixed-point reciprocal shift for the popcount->Q8 scaling (see the neuron
 * loop). 15 keeps acc*recip well inside int32 for every supported layer width
 * (max |acc*recip| ≈ 127<<15 ≈ 4.16e6). */
#define MNV_BNN_RECIP_SHIFT  15

/* =========================================================================
 * BNN DOT PRODUCT — bit-addressed
 *
 * A neuron's weights occupy bits [n*in_sz, n*in_sz+in_sz) of the packed
 * layer buffer, which is NOT byte-aligned unless in_sz % 8 == 0. Reading
 * whole bytes per neuron (the previous approach) mis-aligned the weights for
 * sub-byte widths and counted the last byte's padding bits as agreements,
 * underflowing the accumulator. Read each value's bit directly instead:
 * exactly `len` iterations, no padding, any alignment. Branchless so timing
 * is data-independent (Law II).
 * ========================================================================= */

/**
 * @brief sum_i (w_i == a_i ? +1 : -1), reading bits directly.
 *
 * @param w       Packed weight bits for the whole layer.
 * @param w_off   Bit offset of this neuron's first weight (n * in_sz).
 * @param a        Packed activation bits, starting at bit 0.
 * @param len     Number of binary values (in_sz).
 * @return Signed accumulator in range [-len, +len].
 */
static int16_t bnn_dot_bits(const uint8_t *w, uint32_t w_off,
                            const uint8_t *a, uint16_t len)
{
    int16_t acc = 0;
    for (uint16_t i = 0; i < len; i++) {
        /* uint32: a single layer with in_sz*out_sz >= 65536 bits pushes the
         * neuron bit offset past uint16 (would wrap and read wrong weights). */
        uint32_t wi = w_off + (uint32_t)i;
        uint8_t  wb = (uint8_t)((w[wi >> 3] >> (wi & 7u)) & 1u);
        uint8_t  ab = (uint8_t)((a[i  >> 3] >> (i  & 7u)) & 1u);
        /* xor==0 -> agree -> +1 ; xor==1 -> disagree -> -1 (branchless) */
        acc = (int16_t)(acc + 1 - 2 * (int16_t)(wb ^ ab));
    }
    return acc;
}

/* =========================================================================
 * ACTIVATION PACKING
 * Pack int8 activations (sign bit) into bit array.
 * 1 = positive (≥0), 0 = negative (<0)
 * ========================================================================= */

static void pack_activations(const mnv_act_t *acts, uint8_t *packed, uint16_t len)
{
    uint16_t n_bytes = (len + 7u) / 8u;
    for (uint16_t b = 0; b < n_bytes; b++) {
        uint8_t byte = 0;
        for (uint8_t bit = 0; bit < 8u && (b * 8u + bit) < len; bit++) {
            /* 1 if non-negative */
            byte |= (uint8_t)(((uint8_t)(~((uint8_t)acts[b * 8u + bit] >> 7u))) & 1u) << bit;
        }
        packed[b] = byte;
    }
}

/* =========================================================================
 * BNN FORWARD PASS
 * ========================================================================= */

/* Packed activation scratch — must hold the widest layer's worth of bits,
 * not just layer 0 (a hidden layer can be wider).
 * NOTE: file-scope (not in mnv_ctx_t) -> single-context, not reentrant. Fine
 * for one-inference-at-a-time embedded use; wiped each layer, not by
 * mnv_destroy(). */
#define MNV_BNN_PACKED_BYTES  ((MNV_MAX_ACT_WIDTH + 7u) / 8u)
static uint8_t packed_src[MNV_BNN_PACKED_BYTES];

mnv_status_t mnv_bnn_forward(mnv_ctx_t          *ctx,
                              const mnv_model_t  *model,
                              const mnv_act_t    *input,
                              mnv_act_t          *output,
                              mnv_chacha20_ctx_t *chacha)
{
    mnv_status_t status;

    mnv_act_t *src = ctx->buf_a;
    mnv_act_t *dst = ctx->buf_b;

    /* Copy input */
    for (uint16_t i = 0; i < MNV_INPUT_SIZE; i++) src[i] = input[i];
    uint16_t src_size = MNV_INPUT_SIZE;

    /* Ciphertext is a flat stream: [packed W][int8 b] per layer, in order.
     * The ChaCha context advances the keystream internally; we must advance
     * the *ciphertext* pointer by the same amount each step or layer >0
     * decrypts the wrong bytes. */
    const uint8_t *ct     = model->encrypted_weights;
    uint32_t       ct_off = 0U;

    for (uint8_t layer = 0; layer < model->num_layers; layer++) {
        const mnv_layer_desc_t *ld = &model->layers[layer];
        uint16_t in_sz    = ld->input_size;
        uint16_t out_sz   = ld->output_size;
        uint32_t w_bytes  = ((uint32_t)in_sz * (uint32_t)out_sz + 7u) / 8u;

        /* Decrypt packed weights */
        mnv_chacha20_decrypt(chacha, ct + ct_off,
                             (uint8_t *)ctx->weight_scratch, w_bytes);
        ct_off += w_bytes;

        /* Decrypt this layer's int8 biases (one per output neuron). */
        mnv_bias_t bias_scratch[MNV_CTX_BUF_SIZE];
        uint16_t   bias_bytes = (uint16_t)(out_sz * sizeof(mnv_bias_t));
        mnv_chacha20_decrypt(chacha, ct + ct_off,
                             (uint8_t *)bias_scratch, bias_bytes);
        ct_off += bias_bytes;

        /* Pack input activations */
        pack_activations(src, packed_src, in_sz);

        /* Popcount->Q8 scaling reciprocal. The old code scaled each neuron with
         * (acc*127)/in_sz — a runtime integer DIVISION whose dividend (acc) is a
         * secret intermediate. That divide is variable-latency on cores with a
         * hardware divider (Cortex-M4 SDIV) and on the host, so its timing leaks
         * the accumulator: a Law II violation the Q8 branchless-clamp work never
         * reached. Here the division is done ONCE per layer, over the PUBLIC
         * layer width in_sz only (leaks nothing secret); the per-neuron path is
         * then a data-independent multiply + arithmetic shift. */
        uint16_t isz   = (in_sz != 0U) ? in_sz : 1U;   /* in_sz>0 guaranteed by mnv_init */
        /* Target range is the int8 activation range [-127,127] (NOT MNV_Q_SCALE,
         * which is 1 under MNV_QUANT_BINARY); mirrors the old literal 127. */
        int32_t  recip = (((int32_t)127 << MNV_BNN_RECIP_SHIFT)
                          + (int32_t)(isz >> 1)) / (int32_t)isz;   /* round(127*2^15 / in_sz) */

        /* For each output neuron */
        for (uint16_t n = 0; n < out_sz; n++) {
            /* Weights for neuron n start at bit n*in_sz in the packed buffer. */
            int16_t acc = bnn_dot_bits((const uint8_t *)ctx->weight_scratch,
                                       (uint32_t)n * (uint32_t)in_sz, packed_src, in_sz);

            /* Scale to Q8: acc ∈ [-in_sz, +in_sz] -> [-127, +127], constant-time
             * (reciprocal multiply + shift, no data-dependent branch/divide). */
            int32_t scaled = ((int32_t)acc * recip) >> MNV_BNN_RECIP_SHIFT;
            scaled += (int32_t)(int8_t)bias_scratch[n];
            /* Branchless clamp (Law II) — was a data-dependent ternary. |scaled|
             * <= ~255 here, so the narrowing to mnv_acc_t is value-preserving. */
            mnv_act_t pre_act = mnv_q8_clamp((mnv_acc_t)scaled);

            /* Sign activation (hidden, branchless mask) or linear (output); the
             * switch is on the PUBLIC layer activation, not on any secret. BNN
             * never uses the sigmoid/tanh LUTs, so there is no LUT-vs-non-LUT
             * timing disparity to equalize with a blinded dummy scan here. */
            dst[n] = mnv_apply_activation(ld->activation, pre_act);
        }

        mnv_secure_zero(ctx->weight_scratch, w_bytes);
        mnv_secure_zero(bias_scratch,   bias_bytes);
        mnv_secure_zero(packed_src,     sizeof(packed_src));

        status = mnv_canary_check(ctx);
        if (status != MNV_OK) return MNV_ERR_GLITCH;

        mnv_act_t *tmp = src; src = dst; dst = tmp;
        src_size = out_sz;
        (void)src_size;
    }

    for (uint16_t i = 0; i < MNV_OUTPUT_SIZE; i++) output[i] = src[i];
    return MNV_OK;
}

#endif /* MNV_ARCH_BNN */
