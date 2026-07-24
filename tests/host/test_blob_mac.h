/**
 * @file test_blob_mac.h
 * @brief Shared test helper: compute a model's weight-blob MAC the way the
 *        engine does — BLAKE2s(k_mac, S || ciphertext), where S is the
 *        structural preamble (see src/security/mnv_struct_auth.h).
 *
 * Host tests build an encrypted blob in-process and must MAC it exactly as
 * mnv_init() will, or the model would be rejected. Centralized here so all
 * tests agree with the engine by construction (not by copy-paste).
 */
#ifndef TEST_BLOB_MAC_H
#define TEST_BLOB_MAC_H

#include "minerva.h"
#include "mnv_blake2s.h"
#include "mnv_struct_auth.h"

/* @p model must have its structural fields (version, num_layers, layers[]) set;
 * crypto->mac need NOT be set yet (S does not depend on it). */
static inline void test_blob_mac(const mnv_model_t *model,
                                 const uint8_t     *k_mac,
                                 const uint8_t     *ct,
                                 uint32_t           ct_len,
                                 uint8_t           *mac_out)
{
    uint8_t sbuf[MNV_STRUCT_MAX_BYTES];
    size_t  slen = mnv_struct_serialize(model, sbuf);
    mnv_blake2s_ctx_t bc;
    mnv_blake2s_init(&bc, k_mac, 32);
    mnv_blake2s_update(&bc, sbuf, (uint32_t)slen);
    mnv_blake2s_update(&bc, ct, ct_len);
    mnv_blake2s_final(&bc, mac_out);
}

#endif /* TEST_BLOB_MAC_H */
