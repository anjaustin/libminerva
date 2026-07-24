/**
 * @file simavr_runner.c
 * @brief Host-side libsimavr driver: load an AVR firmware ELF, run it on a
 *        cycle-accurate ATmega328P, and read a one-byte result symbol from SRAM.
 *
 * Used by tests/host/test_avr_sim.sh to actually EXECUTE the AVR code path
 * (PROGMEM flash reads via pgm_read, the Harvard descriptor/crypto-header RAM
 * reads, ChaCha/BLAKE2s, the blinded-LUT pgm_read) on a simulated MCU — the one
 * thing host tests cannot cover. The firmware writes 0xA5 (PASS) or 0x5A (FAIL)
 * to a global; pass that global's SRAM offset (from `avr-nm`, low 16 bits) as
 * argv[2].
 *
 * Build: cc -I<simavr>/include/simavr simavr_runner.c <simavr>/lib/libsimavr.a
 *           -L<libelf>/lib -lelf -o simavr_runner
 * Exit: 0 iff result == 0xA5 (PASS).
 */
#include <stdio.h>
#include <stdlib.h>
#include "sim_avr.h"
#include "sim_elf.h"

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <elf> <result_addr_hex>\n", argv[0]); return 2; }
    const char*  elf  = argv[1];
    unsigned     addr = (unsigned)strtoul(argv[2], NULL, 16);   /* SRAM offset of result byte */

    elf_firmware_t fw = {{0}};
    if (elf_read_firmware(elf, &fw) != 0) { fprintf(stderr, "elf read failed\n"); return 2; }
    avr_t* avr = avr_make_mcu_by_name("atmega328p");
    if (!avr) { fprintf(stderr, "make_mcu failed\n"); return 2; }
    avr_init(avr);
    avr->frequency = 16000000;
    avr_load_firmware(avr, &fw);

    const unsigned long long max_cycles = 4000000000ULL;   /* generous upper bound */
    unsigned long long i = 0;
    int result = -1;
    for (; i < max_cycles; i++) {
        int st = avr_run(avr);
        unsigned char r = avr->data[addr];
        if (r == 0xA5 || r == 0x5A) { result = r; break; }
        if (st == cpu_Done || st == cpu_Crashed) {
            fprintf(stderr, "cpu stopped (state=%d) after %llu steps, byte=0x%02X\n", st, i, r);
            result = r; break;
        }
    }
    printf("steps=%llu result=0x%02X -> %s\n",
           i, (unsigned)(result & 0xFF),
           result == 0xA5 ? "PASS" : result == 0x5A ? "FAIL" : "INCONCLUSIVE");
    return (result == 0xA5) ? 0 : 1;
}
