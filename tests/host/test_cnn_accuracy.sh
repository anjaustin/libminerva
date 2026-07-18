#!/usr/bin/env bash
#
# CNN1D quantization-accuracy test (H4).
#
# Measures how faithfully the Q8 CNN engine reproduces the FLOAT model's
# decisions (argmax agreement on a held-out test set), for the heuristic dense
# shift vs a --calibrate'd shift. A wrong shift saturates or wastes the output
# range and collapses the decisions; calibration derives the shift from data.
#
# Asserts: the calibrated model reaches high argmax agreement AND is at least as
# good as the heuristic. Skips without python3/numpy.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CC="${CC:-cc}"; PY="${PYTHON:-python3}"
COMPILER="$ROOT/compiler/minerva_compile.py"
# Thresholds reflect quantization FIDELITY to the float model on a RANDOM
# (untrained) 4-class model — decisions sit near class boundaries, so absolute
# agreement is modest even at best; a trained model scores higher. The point is
# that calibration tracks the float model far better than the heuristic shift
# (which over-shifts and collapses to near-random ~25%).
MIN_CALIB_AGREE=40      # percent (well above the 25% random baseline)
MIN_MARGIN=15           # calibrated must beat heuristic by at least this much

if ! command -v "$PY" >/dev/null 2>&1 || ! "$PY" -c 'import numpy' >/dev/null 2>&1; then
    echo "=== cnn_accuracy === SKIP (no python3/numpy)"; exit 0
fi

echo "=== cnn_accuracy ==="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
IN=24; K=4; F=6; POOL=2; OUT=4
INC="-I$ROOT/include -I$ROOT/src/core -I$ROOT/src/security -I$ROOT/src/arch -I$ROOT/src/hal"
SRC="$ROOT/src/core/mnv_fixed.c $ROOT/src/core/mnv_engine.c $ROOT/src/arch/mnv_cnn1d.c \
     $ROOT/src/security/mnv_chacha20.c $ROOT/src/security/mnv_blake2s.c \
     $ROOT/src/security/mnv_ct.c $ROOT/src/security/mnv_lut.c \
     $ROOT/src/security/mnv_outauth.c $ROOT/src/hal/mnv_hal_host.c"

# 1. random CNN with LARGE dense weights (so the heuristic shift over-shifts),
#    plus calibration + held-out test inputs, and the float-model argmax labels.
"$PY" - "$TMP" "$IN" "$K" "$F" "$POOL" "$OUT" <<'PY'
import sys, numpy as np
d,IN,K,F,POOL,OUT=sys.argv[1],*map(int,sys.argv[2:7])
rng=np.random.RandomState(11); cl=IN-K+1; pl=cl//POOL; FLAT=F*pl
cw=(rng.randn(F,K)*0.8).astype(np.float32); cb=(rng.randn(F)*0.1).astype(np.float32)
dw=(rng.randn(FLAT,OUT)*2.5).astype(np.float32); db=(rng.randn(OUT)*0.1).astype(np.float32)
np.savez(d+"/cnn.npz",conv_w=cw,conv_b=cb,dense_w=dw,dense_b=db,
         input_len=np.int64(IN),pool_size=np.int64(POOL))
Xc=np.clip(rng.randn(400,IN)*0.5,-1,1).astype(np.float32)      # calibration
Xt=np.clip(rng.randn(200,IN)*0.5,-1,1).astype(np.float32)      # held-out test
np.savez(d+"/calib.npz",X=Xc)
# float-model forward (conv->relu->maxpool->flatten filter-major->dense) argmax
def fwd(x):
    conv=np.zeros((F,cl),dtype=np.float32)
    for f in range(F):
        for i in range(cl): conv[f,i]=max(0.0,float(cw[f]@x[i:i+K])+cb[f])
    feat=np.array([conv[f,p*POOL:(p+1)*POOL].max() for f in range(F) for p in range(pl)],dtype=np.float32)
    return feat@dw+db
lab=np.array([int(np.argmax(fwd(x))) for x in Xt])
np.save(d+"/labels.npy",lab)
# Q8 test inputs (round(x*127)); one line per sample for the harness
with open(d+"/inputs.txt","w") as fh:
    q=np.clip(np.round(Xt*127),-128,127).astype(int)
    fh.write(f"{len(q)}\n")
    for row in q: fh.write(" ".join(map(str,row))+"\n")
PY

"$PY" "$COMPILER" --gen-key "$TMP/k.bin" >/dev/null 2>&1 || { echo "  gen-key FAILED"; exit 1; }

# secrets.h for the harness
{
  printf '#ifndef S\n#define S\n#include <stdint.h>\nstatic const uint8_t kb[32]={'
  "$PY" - "$TMP/k.bin" <<'PY'
import sys; sys.stdout.write(','.join(str(b) for b in open(sys.argv[1],'rb').read(32)))
PY
  printf '};\n#define MNV_DEVICE_KEY kb\n#endif\n'
} > "$TMP/secrets.h"

# agreement% for a given compile (heuristic vs calibrated)
run_variant() {  # $1 = label, $2... = extra compiler args
    local label="$1"; shift
    local od="$TMP/$label"; mkdir -p "$od"
    "$PY" "$COMPILER" "$TMP/cnn.npz" --key "$TMP/k.bin" --target host "$@" --out-dir "$od" >"$od/log" 2>&1 \
        || { echo "  compile ($label) FAILED"; cat "$od/log"; return 1; }
    cp "$TMP/secrets.h" "$od/"
    if ! $CC -std=c11 -w -DMNV_TARGET_HOST -DMNV_ARCH_CNN1D -I"$od" $INC \
            "$ROOT/tests/host/test_cnn_accuracy_harness.c" "$od/weights.c" $SRC -o "$od/h" 2>"$od/cc.err"; then
        echo "  build ($label) FAILED"; cat "$od/cc.err"; return 1
    fi
    "$od/h" < "$TMP/inputs.txt" > "$od/pred.txt" || { echo "  run ($label) FAILED"; return 1; }
    "$PY" - "$TMP/labels.npy" "$od/pred.txt" <<'PY'
import sys, numpy as np
lab=np.load(sys.argv[1]); pred=np.loadtxt(sys.argv[2],dtype=int)
print(f"{100.0*np.mean(lab==pred):.1f}")
PY
}

sh=$("$PY" - "$IN" "$K" "$F" "$POOL" <<'PY'
import sys; IN,K,F,POOL=map(int,sys.argv[1:5]); FLAT=F*((IN-K+1)//POOL); print((FLAT-1).bit_length()+7)
PY
)
a_heur=$(run_variant heuristic) || exit 1
a_cal=$(run_variant calibrated --calibrate "$TMP/calib.npz") || exit 1
echo "  heuristic  shift=$sh  argmax agreement vs float model: ${a_heur}%"
echo "  calibrated shift(data-derived)  argmax agreement vs float model: ${a_cal}%"

pass=$("$PY" - "$a_heur" "$a_cal" "$MIN_CALIB_AGREE" "$MIN_MARGIN" <<'PY'
import sys
h,c,m,mar=map(float,sys.argv[1:5])
print("yes" if (c>=m and c>=h+mar) else "no")
PY
)
if [ "$pass" = yes ]; then
    echo "  calibrated >= ${MIN_CALIB_AGREE}% and beats heuristic by >= ${MIN_MARGIN} pts  PASS"
    echo "CNN ACCURACY TEST PASSED"; exit 0
else
    echo "  calibrated below threshold or not clearly better than heuristic  FAIL"; exit 1
fi
