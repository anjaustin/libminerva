# Makefile — Minerva ATmega328P on-target self-test (H3 scaffold)
#
# UNTESTED in the fix environment (no avr-gcc there). Builds a self-contained
# self-test that runs the full engine pipeline against an in-RAM model and
# signals PASS/FAIL on D13 (and in `selftest_result`, readable under simavr).
#
#   make            # build selftest.elf / .hex
#   make size       # show flash/SRAM usage
#   make sim        # run under simavr if installed (reads D13 / selftest_result)
#   make flash      # flash to a connected Uno via avrdude

MCU     = atmega328p
F_CPU   = 16000000UL
CC      = avr-gcc
OBJCOPY = avr-objcopy
SIZE    = avr-size
MINERVA = ../..

# MNV_NO_PROGMEM_WEIGHTS: this self-test builds its encrypted blob in RAM at
# runtime, so the engine must read it from RAM, not pgm_read it from flash.
# Without this the blob read returns garbage on a Harvard AVR and the MAC fails
# (the self-test returned FAIL under simavr until this was added). The activation
# LUTs remain in PROGMEM; the compiler-emitted classify example keeps weights in
# PROGMEM (that path is validated by tests/host/test_avr_sim.sh).
CFLAGS = -mmcu=$(MCU) -DF_CPU=$(F_CPU) -DMNV_TARGET_ATMEGA328P \
         -DMNV_ARCH_MLP -DMNV_NO_PROGMEM_WEIGHTS \
         -DMNV_INPUT_SIZE=8 -DMNV_LAYER_0_SIZE=8 -DMNV_LAYER_1_SIZE=8 \
         -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=3 \
         -Os -std=c11 -Wall -Wextra -ffunction-sections -fdata-sections \
         -I$(MINERVA)/include -I$(MINERVA)/src/core -I$(MINERVA)/src/security \
         -I$(MINERVA)/src/arch -I$(MINERVA)/src/hal
LDFLAGS = -mmcu=$(MCU) -Wl,--gc-sections

SRCS = selftest.c \
       $(MINERVA)/src/core/mnv_fixed.c \
       $(MINERVA)/src/core/mnv_engine.c \
       $(MINERVA)/src/arch/mnv_mlp.c \
       $(MINERVA)/src/security/mnv_chacha20.c \
       $(MINERVA)/src/security/mnv_blake2s.c \
       $(MINERVA)/src/security/mnv_ct.c \
       $(MINERVA)/src/security/mnv_lut.c \
       $(MINERVA)/src/security/mnv_outauth.c \
       $(MINERVA)/src/hal/mnv_hal_avr.c

all: selftest.hex
	@$(SIZE) --mcu=$(MCU) --format=avr selftest.elf

selftest.elf: $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

selftest.hex: selftest.elf
	$(OBJCOPY) -O ihex -R .eeprom $< $@

size: selftest.elf
	$(SIZE) --mcu=$(MCU) --format=avr selftest.elf

# Requires simavr (https://github.com/buserror/simavr). Watch D13 / read
# `selftest_result` (0xA5 = PASS, 0x5A = FAIL) via a simavr harness.
sim: selftest.elf
	@command -v simavr >/dev/null 2>&1 && simavr -m $(MCU) -f $(F_CPU) selftest.elf \
	 || echo "simavr not installed"

flash: selftest.hex
	avrdude -p $(MCU) -c arduino -P /dev/ttyUSB0 -b 115200 -U flash:w:$<:i

clean:
	rm -f selftest.elf selftest.hex

.PHONY: all size sim flash clean
