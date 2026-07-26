/**
 * @file mnv_hal.h
 * @brief Hardware abstraction layer interface.
 *
 * Deliberately minimal. The engine reads flash via pgm_read_byte directly and
 * returns error codes rather than taking over control flow, so the earlier
 * flash-read and critical-section wrappers were never called and were removed.
 * mnv_hal_fatal() is the one app-facing utility: an unrecoverable-error halt
 * (watchdog reset on AVR) — see the atmega328p_classify example and threat
 * model §4.4.
 */
#ifndef MNV_HAL_H
#define MNV_HAL_H

#include "mnv_types.h"

void mnv_hal_fatal(void);

#endif /* MNV_HAL_H */
