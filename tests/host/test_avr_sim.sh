#!/usr/bin/env bash
#
# On-target (simulated) AVR validation via simavr.
#
# Host tests cannot exercise the Harvard-architecture AVR code path: PROGMEM
# flash reads (pgm_read of the weight blob and the activation LUTs), the RAM
# descriptor/crypto-header reads the AVR metadata fix depends on, and the AVR
# codegen of the constant-time helpers. This runs the real firmware on a
# cycle-accurate ATmega328P (simavr) and checks two paths:
#
#   1. PROGMEM weights (the real deployment path): compile a model, compute the
#      output with the trusted HOST engine, then run the SAME model on simulated
#      AVR with weights in flash and require a bit-identical result.
#   2. RAM-blob self-test (examples/atmega328p_selftest): builds its blob in RAM
#      at runtime and runs init/run/verify vs an in-firmware reference.
#
# Requires: avr-gcc (+ avr-libc), simavr (libsimavr + headers), libelf, and for
# path 1 python3+numpy. SKIPS cleanly (exit 0) if any are missing, so it stays
# friendly to CI images without the AVR toolchain.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CC="${CC:-cc}"
PY="${PYTHON:-python3}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

skip() { echo "=== avr_sim === SKIP ($1)"; exit 0; }

# ── locate avr-gcc (PATH, or a Homebrew keg) ─────────────────────────────────
if ! command -v avr-gcc >/dev/null 2>&1; then
    for p in /opt/homebrew/opt/avr-gcc*/bin /usr/local/opt/avr-gcc*/bin; do
        [ -x "$p/avr-gcc" ] && { PATH="$p:$PATH"; break; }
    done
fi
command -v avr-gcc >/dev/null 2>&1 || skip "no avr-gcc"

# ── locate simavr (libsimavr + headers) and libelf ───────────────────────────
SIMP="$(brew --prefix simavr 2>/dev/null || true)"
ELFP="$(brew --prefix libelf 2>/dev/null || true)"
SIM_INC=""; SIM_LIB=""
for base in "$SIMP" /usr/local /usr; do
    [ -n "$base" ] && [ -f "$base/include/simavr/sim_avr.h" ] && [ -f "$base/lib/libsimavr.a" ] \
        && { SIM_INC="$base/include/simavr"; SIM_LIB="$base/lib/libsimavr.a"; break; }
done
[ -n "$SIM_INC" ] || skip "no libsimavr"
ELF_LDFLAGS="-lelf"; [ -n "$ELFP" ] && [ -d "$ELFP/lib" ] && ELF_LDFLAGS="-L$ELFP/lib -lelf"

echo "=== avr_sim (avr-gcc $(avr-gcc -dumpversion), simavr) ==="

# ── build the simavr runner ──────────────────────────────────────────────────
if ! $CC -O2 -I"$SIM_INC" "$ROOT/tests/host/simavr_runner.c" "$SIM_LIB" $ELF_LDFLAGS \
        -o "$TMP/runner" 2>"$TMP/runner.err"; then
    echo "  runner build FAILED"; cat "$TMP/runner.err"; exit 1
fi

result_addr() { avr-nm "$1" | grep -iw "$2" | awk '{print "0x"substr($1,5)}'; }
rc=0

# ── path 2: RAM-blob self-test (no python needed) ────────────────────────────
if make -C "$ROOT/examples/atmega328p_selftest" clean >/dev/null 2>&1 \
   && make -C "$ROOT/examples/atmega328p_selftest" >/dev/null 2>&1; then
    elf="$ROOT/examples/atmega328p_selftest/selftest.elf"
    if "$TMP/runner" "$elf" "$(result_addr "$elf" selftest_result)" | grep -q PASS; then
        echo "  RAM-blob self-test on ATmega328P  PASS"
    else
        echo "  RAM-blob self-test on ATmega328P  FAIL"; rc=1
    fi
    make -C "$ROOT/examples/atmega328p_selftest" clean >/dev/null 2>&1
else
    echo "  RAM-blob self-test  BUILD FAILED"; rc=1
fi

# ── path 1: PROGMEM weights (needs python3 + numpy) ──────────────────────────
if command -v "$PY" >/dev/null 2>&1 && "$PY" -c 'import numpy' >/dev/null 2>&1; then
    COMPILER="$ROOT/compiler/minerva_compile.py"
    "$PY" "$COMPILER" --gen-key  "$TMP/key.bin"  >/dev/null 2>&1
    "$PY" "$COMPILER" --gen-demo "$TMP/demo.npz" >/dev/null 2>&1
    "$PY" "$COMPILER" "$TMP/demo.npz" --key "$TMP/key.bin" --target atmega328p --quant q8 --out-dir "$TMP/avr" >/dev/null 2>&1
    "$PY" "$COMPILER" "$TMP/demo.npz" --key "$TMP/key.bin" --target host       --quant q8 --out-dir "$TMP/host" >/dev/null 2>&1
    "$PY" - "$TMP/key.bin" > "$TMP/secrets.h" <<'PY'
import sys
k=open(sys.argv[1],'rb').read(32)
print('#ifndef SECRETS_H\n#define SECRETS_H\n#include <stdint.h>')
print('static const uint8_t MNV_DEVICE_KEY[32]={'+','.join('0x%02X'%b for b in k)+'};\n#endif')
PY
    cp "$TMP/secrets.h" "$TMP/avr/secrets.h"; cp "$TMP/secrets.h" "$TMP/host/secrets.h"

    INC="-I$ROOT/include -I$ROOT/src/core -I$ROOT/src/security -I$ROOT/src/arch -I$ROOT/src/hal"
    SEC="$ROOT/src/security/mnv_chacha20.c $ROOT/src/security/mnv_blake2s.c $ROOT/src/security/mnv_ct.c \
         $ROOT/src/security/mnv_lut.c $ROOT/src/security/mnv_outauth.c"
    CORE="$ROOT/src/core/mnv_fixed.c $ROOT/src/core/mnv_engine.c $ROOT/src/arch/mnv_mlp.c"

    # host oracle
    $CC -DMNV_TARGET_HOST -DMNV_ARCH_MLP -I"$TMP/host" $INC \
        "$ROOT/tests/host/avr_progmem_harness.c" "$TMP/host/weights.c" $CORE $SEC \
        "$ROOT/src/hal/mnv_hal_host.c" -std=c11 -O2 -o "$TMP/oracle" 2>"$TMP/oracle.err" \
        || { echo "  PROGMEM oracle build FAILED"; cat "$TMP/oracle.err"; rc=1; }
    ORA="$("$TMP/oracle" 2>/dev/null)"          # "init/run=0 out=-128 -116 98 127"
    read -r E0 E1 E2 E3 <<<"$(echo "$ORA" | sed 's/.*out=//')"

    # AVR firmware with the oracle bytes baked in
    avr-gcc -mmcu=atmega328p -DF_CPU=16000000UL -DMNV_TARGET_ATMEGA328P -DMNV_ARCH_MLP \
        -DEXP0=$E0 -DEXP1=$E1 -DEXP2=$E2 -DEXP3=$E3 -Os -std=c11 \
        -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$TMP/avr" $INC \
        "$ROOT/tests/host/avr_progmem_harness.c" "$TMP/avr/weights.c" $CORE $SEC \
        "$ROOT/src/hal/mnv_hal_avr.c" -o "$TMP/avr_fw.elf" 2>"$TMP/avr.err" \
        || { echo "  PROGMEM AVR build FAILED"; cat "$TMP/avr.err"; rc=1; }

    if [ -f "$TMP/avr_fw.elf" ] && \
       "$TMP/runner" "$TMP/avr_fw.elf" "$(result_addr "$TMP/avr_fw.elf" avr_result)" | grep -q PASS; then
        echo "  PROGMEM weights on ATmega328P == host oracle ($E0 $E1 $E2 $E3)  PASS"
    else
        echo "  PROGMEM weights on ATmega328P  FAIL (oracle: $E0 $E1 $E2 $E3)"; rc=1
    fi

    # ── EEPROM key-override path (the SECURE pattern; threat model §6) ──
    # Provision the key into the ELF .eeprom section (EEMEM); simavr loads it, the
    # firmware reads it into RAM and overrides model.key. Validates the documented
    # secure pattern actually works, and that a wrong/unprovisioned key is rejected.
    "$PY" - "$TMP/key.bin" > "$TMP/keybytes.h" <<'PY'
import sys
k=open(sys.argv[1],'rb').read(32)
print('#define REAL_KEY '+','.join('0x%02X'%b for b in k))
print('#define WRONG_KEY '+','.join('0xFF' for _ in range(32)))
PY
    eek_build() {  # $1 = extra defs, $2 = out elf
        avr-gcc -mmcu=atmega328p -DF_CPU=16000000UL -DMNV_TARGET_ATMEGA328P -DMNV_ARCH_MLP $1 \
            -DEXP0=$E0 -DEXP1=$E1 -DEXP2=$E2 -DEXP3=$E3 -Os -std=c11 \
            -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$TMP" -I"$TMP/avr" $INC \
            "$ROOT/tests/host/avr_eeprom_harness.c" "$TMP/avr/weights.c" $CORE $SEC \
            "$ROOT/src/hal/mnv_hal_avr.c" -o "$2" 2>"$TMP/eek.err"
    }
    if eek_build "" "$TMP/eek_ok.elf" && \
       "$TMP/runner" "$TMP/eek_ok.elf" "$(result_addr "$TMP/eek_ok.elf" avr_result)" | grep -q PASS; then
        echo "  EEPROM key (right) on ATmega328P == host oracle  PASS"
    else
        echo "  EEPROM key (right)  FAIL"; cat "$TMP/eek.err" 2>/dev/null; rc=1
    fi
    if eek_build "-DUSE_WRONG_KEY" "$TMP/eek_bad.elf" && \
       "$TMP/runner" "$TMP/eek_bad.elf" "$(result_addr "$TMP/eek_bad.elf" avr_result)" | grep -q PASS; then
        echo "  EEPROM key (wrong) -> mnv_init rejects (TAMPER)  PASS"
    else
        echo "  EEPROM key (wrong)  FAIL"; rc=1
    fi
else
    echo "  PROGMEM path  SKIP (no python3/numpy)"
fi

[ "$rc" -eq 0 ] && echo "AVR SIM PASSED" || echo "AVR SIM FAILED"
exit $rc
