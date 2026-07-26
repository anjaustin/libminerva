/**
 * @file mnv_endian.h
 * @brief Portable little-endian 32-bit load/store (no unaligned access, no UB).
 *
 * Shared by mnv_blake2s.c and mnv_chacha20.c, which both need LE word access for
 * their state; the two had byte-identical copies of these helpers.
 */
#ifndef MNV_ENDIAN_H
#define MNV_ENDIAN_H

#include <stdint.h>

static inline uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0]        | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

#endif /* MNV_ENDIAN_H */
