/**
 * @file mnv_kdf.h
 * @brief Key domain separation — purpose-specific subkey derivation.
 *
 * The device (master) key is NEVER handed to a cryptographic primitive
 * directly. Each purpose derives its own 32-byte subkey from the master via a
 * keyed BLAKE2s over a one-byte domain label:
 *
 *     subkey = BLAKE2s(key = master_key, message = { label })   (32-byte digest)
 *
 * This is standard key-separation hygiene: the ChaCha20 encryption key, the
 * BLAKE2s weight-MAC key, and the output-authentication key are cryptographically
 * independent, so a weakness (or a key-recovery side channel) in one primitive
 * cannot cross-contaminate another. It also removes the encrypt-and-MAC-with-the-
 * same-key smell (same key feeding both ChaCha20 and the ciphertext MAC).
 *
 * BLAKE2s is used as the KDF because it is already present (zero extra flash),
 * its keyed mode is a PRF, and it is data-independent in time. The derivation is
 * mirrored bit-for-bit by the Python compiler (minerva_compile.py `_kdf`), so the
 * blob a device decrypts/verifies matches what the compiler produced.
 *
 * Header-only (static inline) so no new translation unit needs wiring into the
 * build; it depends only on mnv_blake2s (linked everywhere already).
 */

#ifndef MNV_KDF_H
#define MNV_KDF_H

#include "mnv_types.h"
#include "mnv_blake2s.h"

/* Domain-separation labels. Do not renumber — these are part of the blob format
 * (a device built with different labels than the compiler used will reject every
 * model at the MAC check). */
typedef enum {
    MNV_KDF_LABEL_ENC  = 0x01,  /* ChaCha20 weight-blob encryption   */
    MNV_KDF_LABEL_MAC  = 0x02,  /* BLAKE2s   weight-blob MAC         */
    MNV_KDF_LABEL_OUT  = 0x03,  /* BLAKE2s   output authentication   */
    MNV_KDF_LABEL_PRNG = 0x04,  /* LUT-blinding PRNG default seed    */
} mnv_kdf_label_t;

/**
 * @brief Derive a 32-byte purpose subkey from the 32-byte master key.
 *
 * @param master_key  the device key (MNV_CHACHA20_KEY_SIZE bytes)
 * @param label       purpose label (mnv_kdf_label_t)
 * @param out32       output buffer, MNV_BLAKE2S_DIGEST_SIZE (32) bytes
 *
 * Constant-time with respect to the key (BLAKE2s is data-independent in time).
 * The caller owns @p out32 and should mnv_secure_zero() it after use.
 */
static inline void mnv_kdf_derive(const uint8_t   *master_key,
                                  mnv_kdf_label_t  label,
                                  uint8_t         *out32)
{
    uint8_t lbl = (uint8_t)label;
    mnv_blake2s_mac(master_key, (uint8_t)MNV_CHACHA20_KEY_SIZE,
                    &lbl, 1U, out32);
}

#endif /* MNV_KDF_H */
