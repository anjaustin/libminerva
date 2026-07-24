#!/usr/bin/env bash
#
# CNN1D compiler-emit smoke test (Item 6).
#
# Proves the new CnnCompiler path in minerva_compile.py end to end:
#   1. build a small random 1D-CNN .npz (conv -> ReLU -> maxpool -> dense)
#   2. compile it to weights.c/.h + mnv_model_dims.h
#   3. COMPILE the emitted C against the CNN1D engine (topology auto-propagated
#      via mnv_model_dims.h — no -D shape passed)
#   4. RUN it and compare every output against an INDEPENDENT Python reference
#      that reimplements the engine's conv/relu/pool/dense/shift/bias math over
#      the SAME quantized weights (weights_debug.npz). A wrong serialization
#      order or shift shows up as divergence.
#
# Skips (exit 0) without python3+numpy. Build/numeric failure is a hard error.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CC="${CC:-cc}"; PY="${PYTHON:-python3}"
COMPILER="$ROOT/compiler/minerva_compile.py"
NUM_INPUTS=5

if ! command -v "$PY" >/dev/null 2>&1 || ! "$PY" -c 'import numpy' >/dev/null 2>&1; then
    echo "=== compiler_emit_cnn === SKIP (no python3/numpy)"; exit 0
fi

echo "=== compiler_emit_cnn ==="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# 1. deterministic small CNN model. Topology deliberately differs from EVERY
#    mnv_config.h default (in!=16, K!=4, F!=8, out!=4, shift!=14) so this also
#    exercises CNN-dims auto-propagation: if mnv_model_dims.h failed to reach
#    the engine TUs, the shape/shift would revert to defaults and diverge.
#    in=20 K=3 F=6 pool=2 -> conv_len=18, pool_len=9, flat=54, out=3.
"$PY" - "$TMP/cnn.npz" <<'PY' || { echo "  model gen FAILED"; exit 1; }
import sys, numpy as np
rng=np.random.RandomState(7)
IN,K,F,POOL=20,3,6,2
conv_len=IN-K+1; pool_len=conv_len//POOL; FLAT=F*pool_len; OUT=3
np.savez(sys.argv[1],
         conv_w=(rng.randn(F,K)*0.5).astype(np.float32),
         conv_b=(rng.randn(F)*0.2).astype(np.float32),
         dense_w=(rng.randn(FLAT,OUT)*0.5).astype(np.float32),
         dense_b=(rng.randn(OUT)*0.2).astype(np.float32),
         input_len=np.int64(IN), pool_size=np.int64(POOL))
PY

"$PY" "$COMPILER" --gen-key "$TMP/key.bin" >/dev/null 2>&1 || { echo "  gen-key FAILED"; exit 1; }
"$PY" "$COMPILER" "$TMP/cnn.npz" --key "$TMP/key.bin" --target host \
      --out-dir "$TMP" >"$TMP/compile.log" 2>&1 || { echo "  compile FAILED"; cat "$TMP/compile.log"; exit 1; }

# secrets.h
{
    printf '#ifndef S_H\n#define S_H\n#include <stdint.h>\nstatic const uint8_t mnv_device_key_bytes[32]={'
    "$PY" - "$TMP/key.bin" <<'PY'
import sys; sys.stdout.write(','.join(str(b) for b in open(sys.argv[1],'rb').read(32)))
PY
    printf '};\n#define MNV_DEVICE_KEY mnv_device_key_bytes\n#endif\n'
} > "$TMP/secrets.h"

# 3. build emitted C + CNN engine. No -D topology: mnv_model_dims.h must carry it.
INC="-I$ROOT/include -I$ROOT/src/core -I$ROOT/src/security -I$ROOT/src/arch -I$ROOT/src/hal -I$TMP"
SRC="$ROOT/src/core/mnv_fixed.c $ROOT/src/core/mnv_engine.c $ROOT/src/arch/mnv_cnn1d.c \
     $ROOT/src/security/mnv_chacha20.c $ROOT/src/security/mnv_blake2s.c \
     $ROOT/src/security/mnv_ct.c $ROOT/src/security/mnv_lut.c \
     $ROOT/src/security/mnv_outauth.c $ROOT/src/hal/mnv_hal_host.c"
if ! $CC -std=c11 -Wall -Wextra -fsanitize=address,undefined -g \
        -DMNV_TARGET_HOST -DMNV_ARCH_CNN1D -DNUM_INPUTS=$NUM_INPUTS $INC \
        "$ROOT/tests/host/test_compiler_harness.c" "$TMP/weights.c" $SRC \
        -o "$TMP/emit_cnn" 2>"$TMP/cc.err"; then
    echo "  BUILD of emitted CNN weights.c FAILED"; cat "$TMP/cc.err"; exit 1
fi

"$TMP/emit_cnn" > "$TMP/engine.out" 2>"$TMP/engine.err" || {
    echo "  engine run FAILED"; cat "$TMP/engine.out" "$TMP/engine.err"; exit 1; }

# 4. FULLY INDEPENDENT Python reference: it quantizes the ORIGINAL FLOAT model
#    itself (applying the documented dense transpose and filter-major layout)
#    and reruns the engine's math. It does NOT read the compiler's output, so a
#    wrong transpose/orientation or section order in the compiler diverges from
#    the engine. Quantization mirrors the compiler's symmetric per-tensor scale.
"$PY" - "$TMP/cnn.npz" "$NUM_INPUTS" > "$TMP/ref.out" <<'PY'
import sys, numpy as np
m=np.load(sys.argv[1]); NT=int(sys.argv[2])
conv_w=m['conv_w'].astype(np.float32); conv_b=m['conv_b'].astype(np.float32)
dense_w=m['dense_w'].astype(np.float32); dense_b=m['dense_b'].astype(np.float32)
IN=int(m['input_len']); POOL=int(m['pool_size'])
F,K=conv_w.shape; FLAT,OUT=dense_w.shape
POOL_LEN=(IN-K+1)//POOL; SHIFT=(FLAT-1).bit_length()+7
def q8(a):
    a=a.astype(np.float32).flatten(); s=float(np.max(np.abs(a)))
    if s==0: return np.zeros(len(a),dtype=np.int32)
    return np.clip(np.round(a/s*127),-128,127).astype(np.int32)
cw=q8(conv_w).reshape(F,K)          # filter-major
cb=q8(conv_b)
dW=q8(dense_w.T).reshape(OUT,FLAT)  # transpose to [OUT, FLAT] (independent)
dB=q8(dense_b)
def clamp8(x): return 127 if x>127 else (-128 if x<-128 else int(x))
def gen_input(t,i): return ((t*7+i*13)%81)-40    # MUST match the harness
def fwd(x):
    conv_len=IN-K+1; feat=[0]*FLAT
    for f in range(F):
        conv=[0]*conv_len
        for i in range(conv_len):
            acc=sum(int(cw[f,k])*int(x[i+k]) for k in range(K))
            v=clamp8((acc>>7)+int(cb[f])); conv[i]=max(0,v)
        for p in range(POOL_LEN):
            mv=conv[p*POOL]
            for j in range(1,POOL): mv=max(mv,conv[p*POOL+j])
            feat[f*POOL_LEN+p]=mv
    out=[]
    for n in range(OUT):
        acc=sum(int(dW[n,j])*int(feat[j]) for j in range(FLAT))
        out.append(clamp8((acc>>SHIFT)+int(dB[n])))   # bias in acc domain, single clamp
    return out
print('\n'.join(' '.join(str(v) for v in fwd([gen_input(t,i) for i in range(IN)])) for t in range(NT)))
PY

if diff -u "$TMP/ref.out" "$TMP/engine.out" >"$TMP/diff.out" 2>&1; then
    echo "  emitted CNN1D model compiles, runs, matches Python reference  PASS"
    echo "COMPILER EMIT CNN TEST PASSED"; exit 0
else
    echo "  engine output != Python reference  FAIL"
    echo "  --- (ref = left, engine = right) ---"; cat "$TMP/diff.out"; exit 1
fi
