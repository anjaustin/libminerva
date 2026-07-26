/**
 * @file avr_eeprom_harness.c
 * @brief Validate the runtime EEPROM-key pattern (threat model §6) on AVR.
 *
 * This is the SECURE key-handling pattern the docs recommend and the
 * atmega328p_classify example implements: the device key lives in EEPROM (never
 * compiled into flash), is read into RAM at boot, and mnv_model.key is overridden
 * to point at that buffer. test_avr_sim.sh builds this twice and runs it under
 * simavr (which loads the .eeprom section from the ELF):
 *
 *   - right key  (-U... provisioned via EEMEM = REAL_KEY): mnv_init + mnv_run must
 *     succeed and match the host oracle (-DEXP0..3) -> avr_result = 0xA5.
 *   - wrong key  (-DUSE_WRONG_KEY, EEMEM = 0xFF... = unprovisioned EEPROM): the
 *     MAC must REJECT it (MNV_ERR_TAMPER) so no inference runs -> avr_result =
 *     0xA5 means "correctly rejected".
 *
 * REAL_KEY / WRONG_KEY come from a generated keybytes.h (-include); EXP0..3 from
 * the host oracle. Not built on host (AVR/EEPROM only).
 */
#include "minerva.h"
#include "weights.h"
#include "keybytes.h"
#include <avr/eeprom.h>
#include <string.h>

#ifdef USE_WRONG_KEY
uint8_t EEMEM ee_key[32] = { WRONG_KEY };
#else
uint8_t EEMEM ee_key[32] = { REAL_KEY };
#endif

static mnv_ctx_t ctx;
volatile uint8_t avr_result = 0;   /* read by the simavr runner */

int main(void) {
    uint8_t dev_key[32];
    eeprom_read_block(dev_key, ee_key, sizeof(dev_key));   /* key from EEPROM -> RAM */

    static mnv_model_t model;
    model = mnv_model;
    model.key = dev_key;                                   /* override the flash placeholder */

    int8_t in[MNV_INPUT_SIZE], out[MNV_OUTPUT_SIZE];
    for (int i = 0; i < MNV_INPUT_SIZE;  i++) in[i]  = (int8_t)(17 - 5 * i);
    for (int i = 0; i < MNV_OUTPUT_SIZE; i++) out[i] = 0;

    mnv_status_t s = mnv_init(&ctx, &model);
    if (s == MNV_OK) s = mnv_run(&ctx, in, out);

#ifdef USE_WRONG_KEY
    avr_result = (s == MNV_ERR_TAMPER) ? 0xA5 : 0x5A;      /* wrong key must be rejected */
#else
    uint8_t ok = (s == MNV_OK);
    const int8_t exp[4] = { EXP0, EXP1, EXP2, EXP3 };
    for (int i = 0; i < MNV_OUTPUT_SIZE; i++) if (out[i] != exp[i]) ok = 0;
    avr_result = ok ? 0xA5 : 0x5A;
#endif
    for (;;) { }
}
