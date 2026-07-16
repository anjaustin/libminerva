#!/usr/bin/env bash
#
# Compiles and runs the end-to-end engine tests, one build per architecture
# (the engine is monomorphized at compile time, so each arch/topology needs
# its own binary). Everything is built with ASan + UBSan.
#
# Usage: tests/host/run_engine_tests.sh
# Returns non-zero if any configuration fails to build or any test fails.

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CC="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

INC="-I$ROOT/include -I$ROOT/src/core -I$ROOT/src/security -I$ROOT/src/arch -I$ROOT/src/hal"
COMMON="$ROOT/src/core/mnv_fixed.c $ROOT/src/core/mnv_engine.c \
        $ROOT/src/security/mnv_chacha20.c $ROOT/src/security/mnv_blake2s.c \
        $ROOT/src/security/mnv_ct.c $ROOT/src/security/mnv_lut.c \
        $ROOT/src/security/mnv_outauth.c $ROOT/src/hal/mnv_hal_host.c"
FLAGS="-std=c11 -Wall -Wextra -fsanitize=address,undefined -g"

rc=0
run_cfg() {
    local name="$1"; shift
    local src="$1"; shift
    local arch_src="$1"; shift
    local defs="$*"
    echo "=== $name ==="
    if ! $CC $FLAGS $defs $INC "$ROOT/tests/host/$src" $COMMON "$arch_src" \
            -o "$TMP/$name" 2>"$TMP/$name.berr"; then
        echo "  BUILD FAILED"; cat "$TMP/$name.berr"; rc=1; return
    fi
    if ! "$TMP/$name"; then rc=1; fi
    echo
}

# MLP — documented 8->16->8->4 topology
run_cfg mlp test_engine_mlp.c "$ROOT/src/arch/mnv_mlp.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_MLP \
    -DMNV_INPUT_SIZE=8 -DMNV_LAYER_0_SIZE=16 -DMNV_LAYER_1_SIZE=8 \
    -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=3

# MLP — hidden layer WIDER than input and than layer 0 (per-layer buffer sizing)
run_cfg mlp_wide test_engine_mlp.c "$ROOT/src/arch/mnv_mlp.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_MLP \
    -DMNV_INPUT_SIZE=4 -DMNV_LAYER_0_SIZE=8 -DMNV_LAYER_1_SIZE=16 \
    -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=3

# CNN1D
run_cfg cnn1d test_engine_cnn1d.c "$ROOT/src/arch/mnv_cnn1d.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_CNN1D \
    -DMNV_INPUT_SIZE=16 -DMNV_OUTPUT_SIZE=4 \
    -DMNV_CNN_KERNEL_SIZE=4 -DMNV_CNN_NUM_FILTERS=8 -DMNV_CNN_POOL_SIZE=2 \
    -DMNV_CNN_DENSE_SHIFT=9

# BNN — multi-layer, input widths multiple of 8
run_cfg bnn test_engine_bnn.c "$ROOT/src/arch/mnv_bnn.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_BNN -DMNV_QUANT_BINARY \
    -DMNV_INPUT_SIZE=8 -DMNV_LAYER_0_SIZE=8 -DMNV_LAYER_1_SIZE=8 \
    -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=3

# BNN — hidden layer wider than layer 0 (still multiple of 8: per-layer buffers)
run_cfg bnn_wide test_engine_bnn.c "$ROOT/src/arch/mnv_bnn.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_BNN -DMNV_QUANT_BINARY \
    -DMNV_INPUT_SIZE=8 -DMNV_LAYER_0_SIZE=8 -DMNV_LAYER_1_SIZE=16 \
    -DMNV_OUTPUT_SIZE=8 -DMNV_NUM_LAYERS=3

# BNN — sub-byte input widths (in_sz % 8 != 0: bit-addressed dot product)
run_cfg bnn_odd test_engine_bnn.c "$ROOT/src/arch/mnv_bnn.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_BNN -DMNV_QUANT_BINARY \
    -DMNV_INPUT_SIZE=5 -DMNV_LAYER_0_SIZE=6 -DMNV_LAYER_1_SIZE=5 \
    -DMNV_OUTPUT_SIZE=3 -DMNV_NUM_LAYERS=3

# Confidence-check threshold semantics (only needs mnv_ct.c; threshold > 0)
echo "=== confidence ==="
if ! $CC $FLAGS -DMNV_TARGET_HOST -DMNV_MIN_CONFIDENCE=20 $INC \
        "$ROOT/tests/host/test_confidence.c" "$ROOT/src/security/mnv_ct.c" \
        -o "$TMP/confidence" 2>"$TMP/confidence.berr"; then
    echo "  BUILD FAILED"; cat "$TMP/confidence.berr"; rc=1
elif ! "$TMP/confidence"; then rc=1; fi
echo

# Compiler-emit smoke test — runs the real minerva_compile.py end to end and
# compiles + checks its emitted weights.c against a Python reference. Skips
# cleanly if python3/numpy are unavailable.
if ! bash "$ROOT/tests/host/test_compiler_emit.sh"; then rc=1; fi
echo

if [ "$rc" -eq 0 ]; then echo "ALL ENGINE CONFIGS PASSED"; else echo "ENGINE TESTS FAILED"; fi
exit $rc
