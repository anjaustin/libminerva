#!/usr/bin/env bash
#
# Structural-preamble (S) parity fuzz (R5).
#
# The weight-blob MAC covers S(structure) || iv || counts || ciphertext, where S
# is serialized independently by the engine (mnv_struct_auth.h) and the Python
# compiler (struct_preamble). The compiler-emit tests prove they agree for ONE
# fixed shape; this exercises MANY random MLP topologies — varying layer count,
# widths, and hidden activations — the exact axes S ranges over. For each shape:
# compile with the real compiler, build the emitted weights.c against the engine,
# and require mnv_init() == MNV_OK. If the two S serializations diverged for any
# shape, mnv_init returns MNV_ERR_TAMPER and this test fails.
#
# A negative control confirms the check is not vacuous: one descriptor byte is
# flipped post-compile and mnv_init must then reject it.
#
# Skips cleanly without python3/numpy.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CC="${CC:-cc}"
PY="${PYTHON:-python3}"
COMPILER="$ROOT/compiler/minerva_compile.py"
N="${SPARITY_N:-12}"

if ! command -v "$PY" >/dev/null 2>&1 || ! "$PY" -c 'import numpy' >/dev/null 2>&1; then
    echo "=== sparity_fuzz === SKIP (no python3/numpy)"; exit 0
fi

echo "=== sparity_fuzz ($N random MLP topologies) ==="
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$PY" "$COMPILER" --gen-key "$TMP/key.bin" >/dev/null 2>&1 || { echo "  gen-key FAILED"; exit 1; }

# secrets.h shared by every generated weights.c
{
    printf '#ifndef MNV_SECRETS_H\n#define MNV_SECRETS_H\n#include <stdint.h>\n'
    printf 'static const uint8_t mnv_device_key_bytes[32] = {'
    "$PY" - "$TMP/key.bin" <<'PY'
import sys
sys.stdout.write(','.join(str(b) for b in open(sys.argv[1],'rb').read(32)))
PY
    printf '};\n#define MNV_DEVICE_KEY mnv_device_key_bytes\n#endif\n'
} > "$TMP/secrets.h"

# Emit N random MLP models (deterministic seed -> reproducible failures).
"$PY" - "$TMP" "$N" <<'PY'
import sys, numpy as np
tmp, N = sys.argv[1], int(sys.argv[2])
rng = np.random.default_rng(0xA11CE)
acts = ['relu','sigmoid','tanh']
for k in range(N):
    nl = int(rng.integers(1,4))                 # 1..3 layers
    w  = [int(rng.integers(3,13))]              # input width
    for _ in range(nl): w.append(int(rng.integers(3,13)))
    save = {}
    for i in range(nl):
        save[f'layer_{i}_w']   = (rng.standard_normal((w[i],w[i+1]))*0.5).astype(np.float32)
        save[f'layer_{i}_b']   = (rng.standard_normal(w[i+1])*0.2).astype(np.float32)
        save[f'layer_{i}_act'] = np.array('linear' if i==nl-1 else acts[int(rng.integers(0,3))])
    np.savez(f'{tmp}/m{k}.npz', **save)
    print(f'{k} nl={nl} shape={"->".join(map(str,w))}')
PY

INC_BASE="-I$ROOT/include -I$ROOT/src/core -I$ROOT/src/security -I$ROOT/src/arch -I$ROOT/src/hal"
SRC="$ROOT/src/core/mnv_fixed.c $ROOT/src/core/mnv_engine.c $ROOT/src/arch/mnv_mlp.c \
     $ROOT/src/security/mnv_chacha20.c $ROOT/src/security/mnv_blake2s.c \
     $ROOT/src/security/mnv_ct.c $ROOT/src/security/mnv_lut.c \
     $ROOT/src/security/mnv_outauth.c $ROOT/src/hal/mnv_hal_host.c"

rc=0
for ((k=0; k<N; k++)); do
    od="$TMP/o$k"; mkdir -p "$od"; cp "$TMP/secrets.h" "$od/secrets.h"
    if ! "$PY" "$COMPILER" "$TMP/m$k.npz" --key "$TMP/key.bin" --target host --quant q8 \
            --out-dir "$od" >"$od/compile.log" 2>&1; then
        echo "  [m$k] compile FAILED"; cat "$od/compile.log"; rc=1; continue
    fi
    if ! $CC -std=c11 -O1 -DMNV_TARGET_HOST -DMNV_ARCH_MLP -I"$od" $INC_BASE \
            "$ROOT/tests/host/test_init_only.c" "$od/weights.c" $SRC \
            -o "$od/init" 2>"$od/cc.err"; then
        echo "  [m$k] BUILD FAILED"; cat "$od/cc.err"; rc=1; continue
    fi
    if "$od/init" >"$od/out" 2>&1; then
        : # mnv_init == MNV_OK -> S parity holds for this shape
    else
        echo "  [m$k] mnv_init REJECTED genuine model (status=$(cat "$od/out")) -> S PARITY BROKEN"; rc=1
    fi
done

# Negative control on model 0: flip the first layer's activation to a DIFFERENT
# value (works for any shape: hidden act -> LINEAR, or a lone LINEAR -> RELU) and
# require mnv_init to reject it — proves the S check is live, not vacuous.
od="$TMP/o0"
awk 'BEGIN{done=0}
     /\.activation  = MNV_ACT_/ && !done {
         if ($0 ~ /MNV_ACT_LINEAR/) sub(/MNV_ACT_LINEAR/,"MNV_ACT_RELU");
         else sub(/MNV_ACT_[A-Z]+/,"MNV_ACT_LINEAR");
         done=1 }
     {print}' "$od/weights.c" > "$od/weights_bad.c"
if cmp -s "$od/weights.c" "$od/weights_bad.c"; then
    echo "  negative control: could not mutate an activation -> FAIL"; rc=1
else
    $CC -std=c11 -O1 -DMNV_TARGET_HOST -DMNV_ARCH_MLP -I"$od" $INC_BASE \
        "$ROOT/tests/host/test_init_only.c" "$od/weights_bad.c" $SRC -o "$od/init_bad" 2>/dev/null
    if "$od/init_bad" >/dev/null 2>&1; then
        echo "  negative control: tampered activation ACCEPTED -> FAIL"; rc=1
    else
        echo "  negative control: tampered activation -> rejected  PASS"
    fi
fi

if [ "$rc" -eq 0 ]; then echo "  $N/$N shapes: S parity holds  PASS"; echo "SPARITY FUZZ PASSED";
else echo "SPARITY FUZZ FAILED"; fi
exit $rc
