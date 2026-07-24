/**
 * @file mnv_engine.c
 * @brief Minerva inference engine — v1.1
 *
 * Changes from v1.0:
 *   - Fixed: ChaCha20 offset tracking was stubbed — now fully wired
 *   - Fixed: model pointer stubs removed, mnv_run() demoted to error shim
 *   - Added: mnv_seed_prng() for hardware entropy injection
 *   - Added: blinded LUT dispatch via prng_state in ctx
 *   - Added: output MAC computation (mnv_outauth) after every inference
 *   - Added: mnv_verify_output_with_key(), mnv_get_output_mac()
 */

#include "minerva.h"
#include "mnv_blake2s.h"
#include "mnv_chacha20.h"
#include "mnv_ct.h"
#include "mnv_kdf.h"
#include "mnv_struct_auth.h"
#include "mnv_outauth.h"
#include "mnv_prng.h"
#if defined(MNV_ARCH_MLP)
#include "mnv_mlp.h"
#elif defined(MNV_ARCH_CNN1D)
#include "mnv_cnn1d.h"
#elif defined(MNV_ARCH_BNN)
#include "mnv_bnn.h"
#endif
#include <string.h>

static void engine_chacha_init(mnv_chacha20_ctx_t *chacha,
                                const mnv_model_t  *model)
{
    /* Encrypt/decrypt with a derived subkey, never the master key directly
     * (key domain separation — see mnv_kdf.h). */
    uint8_t k_enc[MNV_CHACHA20_KEY_SIZE];
    mnv_kdf_derive(model->key, MNV_KDF_LABEL_ENC, k_enc);
    mnv_chacha20_init(chacha, k_enc, model->crypto->iv, 0U);
    mnv_secure_zero(k_enc, sizeof(k_enc));
}

static mnv_status_t engine_forward(mnv_ctx_t          *ctx,
                                    const mnv_model_t  *model,
                                    const mnv_act_t    *input,
                                    mnv_act_t          *output,
                                    mnv_chacha20_ctx_t *chacha)
{
#if defined(MNV_ARCH_MLP)
    return mnv_mlp_forward(ctx, model, input, output, chacha);
#elif defined(MNV_ARCH_CNN1D)
    return mnv_cnn1d_forward(ctx, model, input, output, chacha);
#elif defined(MNV_ARCH_BNN)
    return mnv_bnn_forward(ctx, model, input, output, chacha);
#else
    (void)ctx; (void)model; (void)input; (void)output; (void)chacha;
    return MNV_ERR_CONFIG;
#endif
}

/* Compute the BLAKE2s MAC over the encrypted weight blob and constant-time
 * compare it to the stored MAC. Shared by mnv_init() and mnv_verify() so BOTH
 * use the AVR-safe chunked pgm_read path — mnv_verify() previously called
 * mnv_blake2s_verify(), whose plain memcpy of a PROGMEM address reads RAM
 * (garbage) on AVR. model->crypto->mac lives in RAM (see the compiler), so the
 * direct read of it here is correct on every target. */
static mnv_status_t engine_verify_weight_mac(const mnv_model_t *model)
{
    mnv_blake2s_ctx_t bctx;
    /* MAC under a derived subkey, not the master key (domain separation, and it
     * removes the encrypt-and-MAC-with-the-same-key overlap with ChaCha20). The
     * keyed-BLAKE2s init consumes the key into the hash state immediately, so
     * k_mac can be wiped right after. */
    uint8_t k_mac[MNV_CHACHA20_KEY_SIZE];
    mnv_kdf_derive(model->key, MNV_KDF_LABEL_MAC, k_mac);
    mnv_blake2s_init(&bctx, k_mac, (uint8_t)MNV_CHACHA20_KEY_SIZE);
    mnv_secure_zero(k_mac, sizeof(k_mac));

    /* Authenticate the model STRUCTURE first (S), then the ciphertext:
     *   MAC = BLAKE2s(k_mac, S || ciphertext)
     * S is read from the exact fields the engine is about to run on, so a
     * post-compile edit of any layer size/activation/num_layers changes S here
     * and the MAC no longer matches (MNV_ERR_TAMPER). See mnv_struct_auth.h. S
     * lives in RAM on every target (plain reads), unlike the flash blob below. */
    {
        uint8_t sbuf[MNV_STRUCT_MAX_BYTES];
        size_t  slen = mnv_struct_serialize(model, sbuf);
        mnv_blake2s_update(&bctx, sbuf, (uint32_t)slen);
    }
#if defined(MNV_PROGMEM_WEIGHTS)
    /* AVR: read the flash blob in 64B chunks via pgm_read_byte. */
    {
        uint8_t chunk[64];
        uint32_t remaining = model->encrypted_len;   /* <= 0xFFFF on AVR */
        uint32_t offset    = 0;
        while (remaining > 0) {
            uint16_t n = (remaining > 64U) ? 64U : (uint16_t)remaining;
            for (uint16_t i = 0; i < n; i++)
                chunk[i] = pgm_read_byte(model->encrypted_weights + offset + i);
            mnv_blake2s_update(&bctx, chunk, n);
            offset    += n;
            remaining -= n;
        }
        mnv_secure_zero(chunk, sizeof(chunk));
    }
#else
    mnv_blake2s_update(&bctx, model->encrypted_weights, model->encrypted_len);
#endif
    uint8_t computed_mac[MNV_BLAKE2S_DIGEST_SIZE];
    mnv_blake2s_final(&bctx, computed_mac);
    uint8_t diff = mnv_ct_compare(computed_mac, model->crypto->mac,
                                  MNV_BLAKE2S_DIGEST_SIZE);
    mnv_secure_zero(computed_mac, sizeof(computed_mac));
    return (diff == 0) ? MNV_OK : MNV_ERR_TAMPER;
}

/* ── Lifecycle ─────────────────────────────────────────────────────────── */

mnv_status_t mnv_init(mnv_ctx_t *ctx, const mnv_model_t *model)
{
    if (!ctx || !model) return MNV_ERR_NULL;
    mnv_secure_zero(ctx, sizeof(mnv_ctx_t));
    if (model->version != MNV_ABI_VERSION)   return MNV_ERR_CONFIG;
    /* Reject NULL sub-pointers up front: the structural serialization and the
     * integrity check below dereference model->crypto (iv + mac), model->key,
     * and model->encrypted_weights. A tampered descriptor could NULL any of
     * them; catch it here rather than faulting. */
    if (!model->crypto || !model->key || !model->encrypted_weights)
                                             return MNV_ERR_CONFIG;
    /* Bound num_layers for EVERY architecture BEFORE serializing the structural
     * preamble (mnv_struct_auth.h) — its stack buffer is sized to MNV_NUM_LAYERS
     * layers. CNN1D ships num_layers==0 and skips the per-arch descriptor block
     * below, so without this an attacker-tampered CNN1D num_layers would drive
     * the serializer past that buffer (and dereference the NULL layers array).
     * Genuine models satisfy this (CNN1D: 0; MLP/BNN: their real count). */
    if (model->num_layers > MNV_NUM_LAYERS)  return MNV_ERR_CONFIG;
    /* Bound the MAC read length. encrypted_len is attacker-tamperable and drives
     * the BLAKE2s read over the blob; a genuine blob never exceeds the configured
     * flash weight budget. Without this a tampered length walks the hash past the
     * blob — on MCU flash that is a wrong-MAC -> TAMPER at worst, but on a
     * flat-memory host it is a real out-of-bounds read. Reject up front. */
    if (model->encrypted_len == 0U ||
        model->encrypted_len > (uint32_t)MNV_MAX_WEIGHT_BYTES)
                                             return MNV_ERR_CONFIG;
#if defined(MNV_PROGMEM_WEIGHTS)
    /* AVR reads flash weights through 16-bit near pointers (pgm_read_byte), so
     * the encrypted blob must live in the low 64 KB of flash. Larger models on
     * AVR need far-pointer access (pgm_read_byte_far + RAMPZ), which is not
     * implemented. Reject rather than silently wrap the address and compute the
     * MAC over the wrong bytes. (On flat-memory targets — STM32, host — there
     * is no such cap and encrypted_len may use the full uint32 range.) */
    if (model->encrypted_len > 0xFFFFUL)     return MNV_ERR_CONFIG;
#endif
    /* Layer count check for the descriptor-driven architectures (MLP, BNN).
     * CNN1D uses num_layers=0 and derives its shape from the MNV_CNN_* macros. */
#if defined(MNV_ARCH_MLP) || defined(MNV_ARCH_BNN)
    /* Descriptor-driven archs need a non-empty, non-NULL layer array (the upper
     * bound on num_layers was already enforced above). */
    if (model->num_layers == 0 || model->layers == NULL) return MNV_ERR_CONFIG;

    /* Topology-consistency guard (defense-in-depth for compile-time buffer
     * sizing). The ctx buffers in THIS translation unit are sized from the
     * MNV_* macros. If the model's real layer widths disagree — e.g. because
     * the engine was built without the generated mnv_model_dims.h on its
     * include path — proceeding would read/write past buf_a/buf_b/
     * weight_scratch. Reject with MNV_ERR_CONFIG instead of corrupting SRAM.
     * (Layer widths are public topology, not a protected asset, so checking
     * them before the MAC verification below leaks nothing.) */
    if (model->layers[0].input_size != MNV_INPUT_SIZE)   return MNV_ERR_CONFIG;
    if (model->layers[model->num_layers - 1U].output_size != MNV_OUTPUT_SIZE)
                                                         return MNV_ERR_CONFIG;
    for (uint8_t li = 0; li < model->num_layers; li++) {
        uint16_t isz = model->layers[li].input_size;
        uint16_t osz = model->layers[li].output_size;
        if (isz > MNV_MAX_ACT_WIDTH || osz > MNV_MAX_ACT_WIDTH)
                                                         return MNV_ERR_CONFIG;
        if ((uint32_t)isz * (uint32_t)osz > (uint32_t)MNV_MAX_LAYER_WEIGHTS)
                                                         return MNV_ERR_CONFIG;
    }
#endif

    mnv_canary_plant(ctx);
    /* Default LUT-blinding PRNG seed, derived from the device key rather than a
     * public constant (F4). With the old fixed MNV_PRNG_SEED_DEFAULT the entire
     * xorshift mask stream was publicly predictable, so the blinded LUT gave an
     * attacker who knew the (published) seed no protection at all. Deriving it
     * from the master key makes the stream key-dependent — unknown without the
     * key. mnv_seed_prng() with real hardware entropy is still recommended for
     * per-power-cycle trace diversity (a static seed repeats the mask sequence
     * across boots, which averaging can strip). */
    {
        uint8_t seed[MNV_CHACHA20_KEY_SIZE];
        mnv_kdf_derive(model->key, MNV_KDF_LABEL_PRNG, seed);
        uint32_t s = (uint32_t)seed[0]        | ((uint32_t)seed[1] << 8)
                   | ((uint32_t)seed[2] << 16) | ((uint32_t)seed[3] << 24);
        ctx->prng_state = (s != 0U) ? s : (uint32_t)MNV_PRNG_SEED_DEFAULT;
        mnv_secure_zero(seed, sizeof(seed));
    }
    ctx->inference_counter = 0U;

    /* Law I — integrity before anything. Uses the AVR-safe chunked pgm_read
     * path (see engine_verify_weight_mac). */
    mnv_status_t s = engine_verify_weight_mac(model);
    if (s != MNV_OK) { mnv_secure_zero(ctx, sizeof(mnv_ctx_t)); return MNV_ERR_TAMPER; }

    /* Bind the verified model to the context. Inference is permitted only
     * against this exact object (see mnv_run / mnv_run_with_model). */
    ctx->model       = model;
    ctx->verified    = true;
    ctx->initialized = true;
    return MNV_OK;
}

void mnv_destroy(mnv_ctx_t *ctx)
{
    if (ctx) mnv_secure_zero(ctx, sizeof(mnv_ctx_t));
}

/* ── v1.1: PRNG seeding ─────────────────────────────────────────────────── */

void mnv_seed_prng(mnv_ctx_t *ctx, uint32_t seed)
{
    if (!ctx) return;
    ctx->prng_state = (seed != 0U) ? seed : 0xDEADC0DEUL;
}

/* ── Inference ──────────────────────────────────────────────────────────── */

mnv_status_t mnv_run_with_model(mnv_ctx_t         *ctx,
                                 const mnv_model_t *model,
                                 const mnv_act_t   *input,
                                 mnv_act_t         *output)
{
    if (!ctx || !model || !input || !output) return MNV_ERR_NULL;
    if (!ctx->initialized)                   return MNV_ERR_CONFIG;
    if (!ctx->verified)                      return MNV_ERR_TAMPER;
    /* Law I: only the model whose integrity was verified at mnv_init() may
     * run. Reject any other model object — this is what stops an attacker
     * from initializing with a trusted model and then running a different,
     * unverified one through the same (still "verified") context. */
    if (model != ctx->model)                 return MNV_ERR_CONFIG;

    mnv_status_t status;

    /* Pre-inference canary */
    status = mnv_canary_check(ctx);
    if (status != MNV_OK) goto fail_glitch;

    /* Input validation */
#if defined(MNV_ENABLE_INPUT_VALIDATION)
    status = mnv_ct_validate_input(input, MNV_INPUT_SIZE);
    /* Route through fail so a rejected inference uniformly invalidates the
     * output MAC (has_output_mac=false) and wipes buffers — same as the
     * glitch/mismatch paths. Otherwise a prior success's attestation would
     * survive a later rejection (inconsistent per-failure-type behavior). */
    if (status != MNV_OK) { status = MNV_ERR_INPUT; goto fail; }
#endif

    /* Run 1 */
    {
        mnv_chacha20_ctx_t chacha;
        engine_chacha_init(&chacha, model);
        status = engine_forward(ctx, model, input, output, &chacha);
        mnv_chacha20_wipe(&chacha);
        if (status != MNV_OK) goto fail;
    }

    /* Run 2 — double-run comparison */
#if defined(MNV_ENABLE_DOUBLE_RUN)
    {
        mnv_chacha20_ctx_t chacha2;
        engine_chacha_init(&chacha2, model);
        status = engine_forward(ctx, model, input, ctx->run2_buf, &chacha2);
        mnv_chacha20_wipe(&chacha2);
        if (status != MNV_OK) goto fail;
        uint8_t diff = mnv_ct_compare((const uint8_t *)output,
                                       (const uint8_t *)ctx->run2_buf,
                                       MNV_ACT_BYTES(MNV_OUTPUT_SIZE));
        mnv_secure_zero(ctx->run2_buf, MNV_ACT_BYTES(MNV_OUTPUT_SIZE));
        if (diff != 0U) { status = MNV_ERR_MISMATCH; goto fail; }
    }
#endif

    /* Post-inference canary */
    status = mnv_canary_check(ctx);
    if (status != MNV_OK) goto fail_glitch;

    /* Confidence check */
#if defined(MNV_ENABLE_CONFIDENCE_CHECK)
    status = mnv_ct_confidence_check(output, MNV_OUTPUT_SIZE);
    if (status != MNV_OK) { status = MNV_ERR_CONFIDENCE; goto fail; }  /* uniform invalidation (see input path) */
#endif

    /* v1.1: Output MAC */
#if defined(MNV_ENABLE_OUTPUT_AUTH)
    mnv_outauth_compute(ctx, model->key, output, input);
#endif

    return MNV_OK;

fail_glitch:
    status = MNV_ERR_GLITCH;
fail:
    mnv_secure_zero(output,              MNV_ACT_BYTES(MNV_OUTPUT_SIZE));
    mnv_secure_zero(ctx->weight_scratch, sizeof(ctx->weight_scratch));
    mnv_secure_zero(ctx->buf_a,          sizeof(ctx->buf_a));
    mnv_secure_zero(ctx->buf_b,          sizeof(ctx->buf_b));
    mnv_secure_zero(ctx->output_mac,     MNV_OUTPUT_MAC_SIZE);
    ctx->has_output_mac = false;   /* the MAC we just wiped is not verifiable */
    return status;
}

/* Canonical inference entry point. Runs the model bound at mnv_init(). */
mnv_status_t mnv_run(mnv_ctx_t *ctx, const mnv_act_t *input, mnv_act_t *output)
{
    if (!ctx)              return MNV_ERR_NULL;
    if (!ctx->initialized) return MNV_ERR_CONFIG;
    return mnv_run_with_model(ctx, ctx->model, input, output);
}

/* ── Verification ──────────────────────────────────────────────────────── */

mnv_status_t mnv_verify(mnv_ctx_t *ctx, const mnv_model_t *model)
{
    if (!ctx || !model)       return MNV_ERR_NULL;
    if (!ctx->initialized)    return MNV_ERR_CONFIG;
    /* Re-verification must target the model bound at init; otherwise a
     * caller could validate model A and leave the context "verified" while
     * mnv_run() still executes the bound model. */
    if (model != ctx->model)  return MNV_ERR_CONFIG;
    /* Same AVR-safe chunked read as mnv_init (not mnv_blake2s_verify, whose
     * direct memcpy of the PROGMEM blob reads garbage on AVR). */
    mnv_status_t s = engine_verify_weight_mac(model);
    ctx->verified = (s == MNV_OK);
    return s;
}

/* ── v1.1: Output auth API ─────────────────────────────────────────────── */

mnv_status_t mnv_verify_output_with_key(const mnv_ctx_t *ctx,
                                         const uint8_t   *device_key,
                                         const mnv_act_t *input,
                                         const mnv_act_t *output)
{
    if (!ctx || !device_key || !input || !output) return MNV_ERR_NULL;
    return mnv_outauth_verify(ctx, device_key, output, input);
}

mnv_status_t mnv_verify_output(const mnv_ctx_t *ctx,
                                const mnv_act_t *input,
                                const mnv_act_t *output)
{
    if (!ctx || !input || !output) return MNV_ERR_NULL;
    if (!ctx->initialized || !ctx->model) return MNV_ERR_CONFIG;
    /* Uses the device key from the model bound at init. */
    return mnv_outauth_verify(ctx, ctx->model->key, output, input);
}

void mnv_get_output_mac(const mnv_ctx_t *ctx, uint8_t *mac)
{
    if (!ctx || !mac) return;
    memcpy(mac, ctx->output_mac, MNV_OUTPUT_MAC_SIZE);
}

/* mnv_secure_zero and mnv_ct_compare defined in mnv_ct.c */
