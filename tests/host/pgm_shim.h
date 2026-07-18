/**
 * @file pgm_shim.h
 * @brief Harvard-architecture simulation shim for the PROGMEM access-pattern
 *        lock (H3). Force-included (-include) when building the engine for
 *        test_progmem_split.c.
 *
 * On a von-Neumann host, flash and RAM share one address space, so a direct
 * read of a "PROGMEM" pointer works and the AVR bug (direct read of flash =
 * garbage) is invisible. This shim recreates the split: it routes every
 * pgm_read_byte through a test-provided function that redirects the encrypted
 * weight blob to its REAL bytes while the model's pointer aims at a POISONED
 * copy. A correct engine reads the blob only via pgm_read and sees real data; a
 * regressed engine that reads the blob directly hits the poison and fails.
 */
#ifndef MNV_PGM_SHIM_H
#define MNV_PGM_SHIM_H
#include <stdint.h>
#define PROGMEM
uint8_t mnv_test_pgm_read(const void *p);   /* defined in test_progmem_split.c */
#define pgm_read_byte(p) mnv_test_pgm_read((const void *)(p))
#endif
