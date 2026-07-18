#!/usr/bin/env bash
#
# PROGMEM placement lock (H3). Compiles a model for an AVR target and asserts
# the compiler emits the small metadata (crypto header, layer descriptors) in
# RAM and only the large encrypted-weights blob in flash (PROGMEM). This is the
# other half of the AVR metadata fix: the engine reads metadata directly (valid
# only if it is in RAM) and the blob via pgm_read (valid only if it is PROGMEM).
# test_progmem_split.c locks the engine's access pattern; this locks the
# compiler's emission.
#
# Skips without python3/numpy.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${PYTHON:-python3}"
COMPILER="$ROOT/compiler/minerva_compile.py"

if ! command -v "$PY" >/dev/null 2>&1 || ! "$PY" -c 'import numpy' >/dev/null 2>&1; then
    echo "=== progmem_placement === SKIP (no python3/numpy)"; exit 0
fi

echo "=== progmem_placement ==="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

"$PY" "$COMPILER" --gen-key  "$TMP/k.bin" >/dev/null 2>&1 || { echo "  gen-key FAILED";  exit 1; }
"$PY" "$COMPILER" --gen-demo "$TMP/m.npz" >/dev/null 2>&1 || { echo "  gen-demo FAILED"; exit 1; }
"$PY" "$COMPILER" "$TMP/m.npz" --key "$TMP/k.bin" --target atmega328p --out-dir "$TMP" >/dev/null 2>&1 \
    || { echo "  compile FAILED"; exit 1; }

W="$TMP/weights.c"
rc=0
assert_ram()   { if grep -qE "$2.*PROGMEM" "$W"; then echo "  $1 is PROGMEM (want RAM)  FAIL"; rc=1; else echo "  $1 in RAM  PASS"; fi; }
assert_flash() { if grep -qE "$2.*PROGMEM" "$W"; then echo "  $1 in flash (PROGMEM)  PASS"; else echo "  $1 not PROGMEM (want flash)  FAIL"; rc=1; fi; }

assert_ram   "crypto header"       "mnv_crypto_header_t mnv_crypto_hdr"
assert_ram   "layer descriptors"   "mnv_layer_desc_t    mnv_layers|mnv_layer_desc_t mnv_layers"
assert_flash "encrypted weights"   "mnv_encrypted_weights\[\]"

if [ "$rc" -eq 0 ]; then echo "PROGMEM PLACEMENT PASSED"; else echo "PROGMEM PLACEMENT FAILED"; fi
exit $rc
