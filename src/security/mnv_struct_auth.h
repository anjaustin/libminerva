/**
 * @file mnv_struct_auth.h
 * @brief Canonical serialization of the model's STRUCTURE for authentication.
 *
 * The weight-blob MAC authenticates the ciphertext, but the engine also drives
 * inference from the model's *structure* — num_layers and each layer's
 * input_size / output_size / activation (MLP, BNN), or the CNN core dimensions
 * (CNN1D). Those fields live in a mutable descriptor (RAM/flash data), not in
 * the ciphertext, so an attacker who can rewrite the flash image (in scope per
 * docs/threat_model.md §3.1) could change a nonlinearity or a layer width and
 * still pass a ciphertext-only integrity check — altering inference behavior
 * while the device reports "verified" (Law I).
 *
 * Remediation: bind a canonical structural preamble S into the same keyed
 * BLAKE2s as the ciphertext:
 *
 *     MAC = BLAKE2s(key = k_mac,  message = S || ciphertext)
 *
 * S is produced identically by (a) the engine, from the model it is about to
 * run, and (b) the Python compiler, from the model it emits (minerva_compile.py
 * `_struct_preamble`). Any post-compile edit to a structural field changes the
 * engine-side S, so the MAC no longer matches and mnv_init() returns
 * MNV_ERR_TAMPER. As a bonus it also makes an engine/blob shape mismatch (wrong
 * -D dims, or a CNN1D built against the wrong macros) fail loudly at init
 * instead of silently computing garbage.
 *
 * Canonical layout (little-endian, fixed widths — same discipline as mnv_kdf.h):
 *
 *     u8   version            (model->version; must equal MNV_ABI_VERSION)
 *     u8   arch_id            (1 = MLP, 2 = CNN1D, 3 = BNN; compile-time)
 *     u8   num_layers         (model->num_layers)
 *     if num_layers > 0  (MLP / BNN), per layer i:
 *         LE16 input_size
 *         LE16 output_size
 *         u8   activation
 *     else               (CNN1D, num_layers == 0):
 *         LE16 MNV_INPUT_SIZE
 *         LE16 MNV_OUTPUT_SIZE
 *         LE16 MNV_CNN_KERNEL_SIZE
 *         LE16 MNV_CNN_NUM_FILTERS
 *         LE16 MNV_CNN_POOL_SIZE
 *     always, last:
 *         u8[MNV_CHACHA20_IV_SIZE]  crypto->iv            (ChaCha20 nonce)
 *         LE32 crypto->weight_count
 *         LE32 crypto->bias_count
 *
 * The blob length is already implicitly authenticated (the MAC hashes exactly
 * encrypted_len ciphertext bytes), so it is not repeated in S. The IV IS
 * included: it is not part of the ciphertext but selects the decryption
 * keystream, so an unauthenticated IV would let an attacker swap it and decrypt
 * the (authentic) ciphertext into garbage weights while the MAC still passed.
 * weight_count/bias_count are informational (the engine does not consume them)
 * but are bound anyway so NO descriptor field is left outside the MAC.
 *
 * Header-only (static inline) so it links into the engine and every test/host
 * TU with no build wiring, exactly like mnv_kdf.h.
 */

#ifndef MNV_STRUCT_AUTH_H
#define MNV_STRUCT_AUTH_H

#include "mnv_types.h"

/* Architecture id for the preamble — resolved at compile time from the single
 * selected MNV_ARCH_*. Must match minerva_compile.py's arch id. */
#if defined(MNV_ARCH_CNN1D)
#  define MNV_STRUCT_ARCH_ID  2u
#elif defined(MNV_ARCH_BNN)
#  define MNV_STRUCT_ARCH_ID  3u
#else
#  define MNV_STRUCT_ARCH_ID  1u   /* MLP (default) */
#endif

/* Upper bound on the serialized length. 3 header bytes + the per-arch body
 * (MLP/BNN: 5 per layer, num_layers <= MNV_NUM_LAYERS enforced in mnv_init
 * before this runs; CNN1D: 10) + the trailing IV. Take the max body so one
 * stack buffer fits either shape. */
#define MNV_STRUCT_MAX_BYTES \
    (3u + ((MNV_NUM_LAYERS * 5u) > 10u ? (MNV_NUM_LAYERS * 5u) : 10u) \
        + MNV_CHACHA20_IV_SIZE + 8u /* weight_count + bias_count */)

static inline void mnv_struct_put16_(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static inline void mnv_struct_put32_(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8)  & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

/**
 * @brief Serialize the model's structural preamble S into @p out.
 * @return number of bytes written (<= MNV_STRUCT_MAX_BYTES).
 *
 * Reads the SAME fields the engine consumes at run time, so tampering any of
 * them is detected by the MAC. On CNN1D (num_layers == 0) the shape comes from
 * the compile-time MNV_CNN_* macros the engine actually uses.
 */
static inline size_t mnv_struct_serialize(const mnv_model_t *model, uint8_t *out)
{
    size_t o = 0;
    out[o++] = (uint8_t)model->version;
    out[o++] = (uint8_t)MNV_STRUCT_ARCH_ID;
    out[o++] = (uint8_t)model->num_layers;

    /* Per-layer structure (MLP/BNN). The layers != NULL guard matters for a
     * tampered CNN1D model: it ships num_layers==0 with layers==NULL, and an
     * attacker could raise num_layers while leaving layers NULL — without the
     * guard that dereferences NULL. Skipping the loop then yields a preamble
     * that cannot match a genuine one, so the MAC rejects it. mnv_init bounds
     * num_layers <= MNV_NUM_LAYERS, so `out` cannot overflow here. */
    if (model->num_layers > 0u && model->layers != NULL) {
        for (uint8_t i = 0; i < model->num_layers; i++) {
            mnv_struct_put16_(out + o, model->layers[i].input_size);  o += 2;
            mnv_struct_put16_(out + o, model->layers[i].output_size); o += 2;
            out[o++] = (uint8_t)model->layers[i].activation;
        }
    }
#if defined(MNV_ARCH_CNN1D)
    else if (model->num_layers == 0u) {
        mnv_struct_put16_(out + o, (uint16_t)MNV_INPUT_SIZE);      o += 2;
        mnv_struct_put16_(out + o, (uint16_t)MNV_OUTPUT_SIZE);     o += 2;
        mnv_struct_put16_(out + o, (uint16_t)MNV_CNN_KERNEL_SIZE); o += 2;
        mnv_struct_put16_(out + o, (uint16_t)MNV_CNN_NUM_FILTERS); o += 2;
        mnv_struct_put16_(out + o, (uint16_t)MNV_CNN_POOL_SIZE);   o += 2;
    }
#endif

    /* Authenticate the ChaCha20 nonce and the (informational) header counts.
     * Caller guarantees model->crypto != NULL (mnv_init rejects a NULL crypto
     * header before reaching here). */
    for (uint8_t j = 0; j < (uint8_t)MNV_CHACHA20_IV_SIZE; j++)
        out[o++] = model->crypto->iv[j];
    mnv_struct_put32_(out + o, model->crypto->weight_count); o += 4;
    mnv_struct_put32_(out + o, model->crypto->bias_count);   o += 4;

    return o;
}

#endif /* MNV_STRUCT_AUTH_H */
