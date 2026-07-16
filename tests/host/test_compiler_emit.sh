#!/usr/bin/env bash
#
# Compiler-emit smoke test.
#
# Regression guard for the Item-1 bug (minerva_compile.py emitted "}}," per
# layer descriptor, so every generated weights.c failed to compile). This test
# exercises the ONLY documented model-production path end to end:
#
#   1. generate a device key            (minerva_compile.py --gen-key)
#   2. generate + train a demo model    (minerva_compile.py --gen-demo)
#   3. compile it to weights.c/.h        (minerva_compile.py <model> --key ...)
#   4. COMPILE the emitted C with the engine  <-- catches invalid codegen
#   5. RUN it and compare every output against an INDEPENDENT Python Q8
#      reference derived from weights_debug.npz  <-- catches numeric drift
#
# If python3+numpy is unavailable the test SKIPS (exit 0) rather than failing,
# so it stays friendly to minimal CI images. A build or numeric failure is a
# hard error.
#
# Usage: tests/host/test_compiler_emit.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CC="${CC:-cc}"
PY="${PYTHON:-python3}"
COMPILER="$ROOT/compiler/minerva_compile.py"

# Demo topology is fixed by minerva_compile.py --gen-demo (8 -> 16 -> 8 -> 4).
IN=8; H0=16; H1=8; OUT=4; NL=3
NUM_INPUTS=5

if ! command -v "$PY" >/dev/null 2>&1; then
    echo "=== compiler_emit === SKIP (no $PY)"; exit 0
fi
if ! "$PY" -c 'import numpy' >/dev/null 2>&1; then
    echo "=== compiler_emit === SKIP (numpy not installed)"; exit 0
fi

echo "=== compiler_emit ==="
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. key + 2. demo model (+ calibration set)
"$PY" "$COMPILER" --gen-key "$TMP/key.bin"   >/dev/null 2>&1 || { echo "  gen-key FAILED"; exit 1; }
"$PY" "$COMPILER" --gen-demo "$TMP/demo.npz" >"$TMP/demo.log" 2>&1 || { echo "  gen-demo FAILED"; cat "$TMP/demo.log"; exit 1; }

# 3. compile the model to C, with a decrypted-weight dump for the reference
"$PY" "$COMPILER" "$TMP/demo.npz" --key "$TMP/key.bin" --target host --quant q8 \
      --dump-weights --out-dir "$TMP" >"$TMP/compile.log" 2>&1 \
      || { echo "  compile FAILED"; cat "$TMP/compile.log"; exit 1; }

# secrets.h — the generated weights.c references MNV_DEVICE_KEY
{
    printf '#ifndef MNV_SECRETS_H\n#define MNV_SECRETS_H\n#include <stdint.h>\n'
    printf 'static const uint8_t mnv_device_key_bytes[32] = {'
    "$PY" - "$TMP/key.bin" <<'PY'
import sys
sys.stdout.write(','.join(str(b) for b in open(sys.argv[1],'rb').read(32)))
PY
    printf '};\n#define MNV_DEVICE_KEY mnv_device_key_bytes\n#endif\n'
} > "$TMP/secrets.h"

# 4. compile emitted C + engine. NOTE: no -D topology is passed. The generated
#    mnv_model_dims.h (in $TMP, on the include path) must propagate the model
#    shape to EVERY TU via mnv_config.h's __has_include (Item 2). If that
#    mechanism breaks, the engine TUs revert to the mnv_config.h defaults and
#    mnv_init()'s topology guard rejects the model (or ASan trips) — either way
#    this test fails, which is the point.
INC="-I$ROOT/include -I$ROOT/src/core -I$ROOT/src/security -I$ROOT/src/arch -I$ROOT/src/hal -I$TMP"
SRC="$ROOT/src/core/mnv_fixed.c $ROOT/src/core/mnv_engine.c $ROOT/src/arch/mnv_mlp.c \
     $ROOT/src/security/mnv_chacha20.c $ROOT/src/security/mnv_blake2s.c \
     $ROOT/src/security/mnv_ct.c $ROOT/src/security/mnv_lut.c \
     $ROOT/src/security/mnv_outauth.c $ROOT/src/hal/mnv_hal_host.c"

if ! $CC -std=c11 -Wall -Wextra -fsanitize=address,undefined -g \
        -DMNV_TARGET_HOST -DMNV_ARCH_MLP -DNUM_INPUTS=$NUM_INPUTS $INC \
        "$ROOT/tests/host/test_compiler_harness.c" "$TMP/weights.c" $SRC \
        -o "$TMP/emit_harness" 2>"$TMP/cc.err"; then
    echo "  BUILD of emitted weights.c FAILED"; cat "$TMP/cc.err"; exit 1
fi

# 5a. engine output
if ! "$TMP/emit_harness" > "$TMP/engine.out" 2>"$TMP/engine.err"; then
    echo "  engine run FAILED"; cat "$TMP/engine.out" "$TMP/engine.err"; exit 1
fi

# 5b. independent Python Q8 reference (same //128 semantics, same inputs)
"$PY" - "$TMP/weights_debug.npz" "$IN" "$OUT" "$NL" "$NUM_INPUTS" > "$TMP/ref.out" <<'PY'
import sys, numpy as np
dbg, IN, OUT, NL, NT = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
d = np.load(dbg)
def gen_input(t, i):  # MUST match test_compiler_harness.c
    return ((t*7 + i*13) % 81) - 40
def forward(x):
    a = np.clip(np.array(x, dtype=np.int32), -128, 127)
    for i in range(NL):
        W = d[f'W{i}T_q'].astype(np.int32)
        b = d[f'b{i}_q'].astype(np.int32)
        a = np.clip((W @ a)//128 + b, -128, 127)
        if i < NL-1:                       # relu on hidden, linear on output
            a = np.maximum(0, a)
    return a
out = []
for t in range(NT):
    v = forward([gen_input(t, i) for i in range(IN)])
    out.append(' '.join(str(int(x)) for x in v))
print('\n'.join(out))
PY

if diff -u "$TMP/ref.out" "$TMP/engine.out" >"$TMP/diff.out" 2>&1; then
    echo "  emitted model compiles, runs, and matches Python reference  PASS"
    echo "COMPILER EMIT TEST PASSED"
    exit 0
else
    echo "  engine output != Python reference  FAIL"
    echo "  --- (ref = left, engine = right) ---"; cat "$TMP/diff.out"
    exit 1
fi
