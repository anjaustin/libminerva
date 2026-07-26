/**
 * @file mnv_hal_avr.c
 * @brief AVR (ATmega/ATtiny) hardware abstraction layer
 *
 * Handles PROGMEM flash reads for weight access.
 * On AVR, weights live in flash and must be read byte-by-byte
 * via pgm_read_byte() — direct pointer dereference reads SRAM, not flash.
 */

#include "mnv_hal.h"

#if defined(MNV_ARCH_AVR8)
#include <avr/wdt.h>

/**
 * @brief Trigger hardware watchdog reset — used on unrecoverable security error.
 *
 * Enables the WDT with the minimum timeout (15 ms) then spins until it fires.
 * The device reboots rather than continuing in an undefined state after a
 * tamper/glitch detection (threat model §4.4).
 */
void mnv_hal_fatal(void)
{
    wdt_enable(WDTO_15MS);
    while (1) { /* wait for watchdog */ }
}

#endif /* MNV_ARCH_AVR8 */
