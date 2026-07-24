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

# MLP — encrypted blob > 64 KB (260*260 layer-0 = 67600 B; total ~69 KB).
# Regression guard for the uint16 length truncation: pre-fix, encrypted_len,
# the ChaCha decrypt length, and the ciphertext offset all wrapped at 64 KB,
# so mnv_init's MAC covered the wrong bytes and rejected a valid model.
run_cfg mlp_big test_engine_mlp.c "$ROOT/src/arch/mnv_mlp.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_MLP \
    -DMNV_INPUT_SIZE=260 -DMNV_LAYER_0_SIZE=260 -DMNV_LAYER_1_SIZE=4 \
    -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=3

# Structural authentication (audit F1): the MAC now covers S(structure)||ct, so
# a post-compile edit of an activation, an interior width, or num_layers — with
# the ciphertext and stored MAC untouched — is rejected as MNV_ERR_TAMPER.
run_cfg metadata_auth test_metadata_auth.c "$ROOT/src/arch/mnv_mlp.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_MLP \
    -DMNV_INPUT_SIZE=8 -DMNV_LAYER_0_SIZE=16 -DMNV_LAYER_1_SIZE=8 \
    -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=3

# Fuzz mnv_init (R4): single-field mutations of a genuine model — must never
# crash (ASan/UBSan) and never accept a tampered model. 100k iters under CI.
run_cfg fuzz_init test_fuzz_init.c "$ROOT/src/arch/mnv_mlp.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_MLP -DFUZZ_ITERS=100000 \
    -DMNV_INPUT_SIZE=8 -DMNV_LAYER_0_SIZE=16 -DMNV_LAYER_1_SIZE=8 \
    -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=3

# CNN1D
run_cfg cnn1d test_engine_cnn1d.c "$ROOT/src/arch/mnv_cnn1d.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_CNN1D \
    -DMNV_INPUT_SIZE=16 -DMNV_OUTPUT_SIZE=4 \
    -DMNV_CNN_KERNEL_SIZE=4 -DMNV_CNN_NUM_FILTERS=8 -DMNV_CNN_POOL_SIZE=2 \
    -DMNV_CNN_DENSE_SHIFT=9

# CNN1D — kernel blob WIDER than the dense scratch (F*K > OUTPUT*FLAT). Regression
# for the weight_scratch overflow: in=6,K=5,F=2,pool=2 -> F*K=10 vs OUTPUT*FLAT=2.
run_cfg cnn1d_bigkernel test_engine_cnn1d.c "$ROOT/src/arch/mnv_cnn1d.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_CNN1D \
    -DMNV_INPUT_SIZE=6 -DMNV_OUTPUT_SIZE=1 \
    -DMNV_CNN_KERNEL_SIZE=5 -DMNV_CNN_NUM_FILTERS=2 -DMNV_CNN_POOL_SIZE=2 \
    -DMNV_CNN_DENSE_SHIFT=7

# BNN — a single layer with in_sz*out_sz >= 65536 bits, so the neuron bit offset
# (n*in_sz) exceeds uint16. Regression for the bnn_dot_bits offset-wrap fix.
run_cfg bnn_bigoffset test_engine_bnn.c "$ROOT/src/arch/mnv_bnn.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_BNN -DMNV_QUANT_BINARY \
    -DMNV_INPUT_SIZE=256 -DMNV_LAYER_0_SIZE=264 -DMNV_LAYER_1_SIZE=8 \
    -DMNV_OUTPUT_SIZE=8 -DMNV_NUM_LAYERS=3

# BNN — accumulator wider than INT16_MAX (audit F2). Single linear layer of
# width 40000, all-agree, so the popcount accumulator = 40000 (wraps int16).
run_cfg bnn_overflow test_bnn_overflow.c "$ROOT/src/arch/mnv_bnn.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_BNN -DMNV_QUANT_BINARY \
    -DMNV_INPUT_SIZE=40000 -DMNV_LAYER_0_SIZE=4 -DMNV_LAYER_1_SIZE=4 \
    -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=1

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

# PROGMEM flash-read path + AVR >64 KB near-pointer guard (Item 4). Forces
# MNV_PROGMEM_WEIGHTS on (host pgm_read_byte is a no-op) to cover the chunked
# BLAKE2s read in mnv_init that the true-host configs above no longer exercise.
run_cfg progmem_guard test_progmem_guard.c "$ROOT/src/arch/mnv_mlp.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_MLP -DMNV_PROGMEM_WEIGHTS \
    -DMNV_INPUT_SIZE=8 -DMNV_LAYER_0_SIZE=8 -DMNV_LAYER_1_SIZE=8 \
    -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=3

# PROGMEM access-pattern lock (H3): simulate the Harvard flash/RAM split with a
# poisoned blob + redirecting pgm_read, so a direct (non-pgm_read) blob read is
# caught. Built with the shim force-included and MNV_PROGMEM_WEIGHTS forced on.
echo "=== progmem_split ==="
if ! $CC $FLAGS -include "$ROOT/tests/host/pgm_shim.h" \
        -DMNV_TARGET_HOST -DMNV_ARCH_MLP -DMNV_PROGMEM_WEIGHTS \
        -DMNV_INPUT_SIZE=8 -DMNV_LAYER_0_SIZE=8 -DMNV_LAYER_1_SIZE=8 \
        -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=3 $INC \
        "$ROOT/tests/host/test_progmem_split.c" \
        "$ROOT/src/core/mnv_fixed.c" "$ROOT/src/core/mnv_engine.c" "$ROOT/src/arch/mnv_mlp.c" \
        "$ROOT/src/security/mnv_chacha20.c" "$ROOT/src/security/mnv_blake2s.c" \
        "$ROOT/src/security/mnv_ct.c" "$ROOT/src/security/mnv_lut.c" \
        "$ROOT/src/security/mnv_outauth.c" "$ROOT/src/hal/mnv_hal_host.c" \
        -o "$TMP/progmem_split" 2>"$TMP/split.berr"; then
    echo "  BUILD FAILED"; cat "$TMP/split.berr"; rc=1
elif ! "$TMP/progmem_split"; then rc=1; fi
echo

# Constant-time timing-leakage test (H2): mnv_ct_compare vs a leaky early-exit
# reference, dudect-style Welch t-test. Self-validating (skips if the host is
# too noisy to detect even the known leak). Needs -lm.
echo "=== ct_timing ==="
if ! $CC $FLAGS -DMNV_TARGET_HOST $INC \
        "$ROOT/tests/host/test_ct_timing.c" "$ROOT/src/security/mnv_ct.c" -lm \
        -o "$TMP/ct_timing" 2>"$TMP/ctt.berr"; then
    echo "  BUILD FAILED"; cat "$TMP/ctt.berr"; rc=1
elif ! "$TMP/ct_timing"; then rc=1; fi
echo

# Constant-time branch audit (H2). AVR-only meaningful; skips without avr-gcc.
if ! bash "$ROOT/tests/host/check_ct_branches.sh"; then rc=1; fi
echo

# PROGMEM placement lock (H3): compiler must emit metadata in RAM, blob in
# flash. Skips without python3/numpy.
if ! bash "$ROOT/tests/host/check_progmem_placement.sh"; then rc=1; fi
echo

# Output-MAC counter guard + wraparound (Item 9). Driven against outauth +
# crypto only; observes via verify() return values.
echo "=== outauth_counter ==="
if ! $CC $FLAGS -DMNV_TARGET_HOST -DMNV_ARCH_MLP \
        -DMNV_INPUT_SIZE=8 -DMNV_OUTPUT_SIZE=4 -DMNV_LAYER_0_SIZE=16 \
        -DMNV_LAYER_1_SIZE=8 -DMNV_NUM_LAYERS=3 $INC \
        "$ROOT/tests/host/test_outauth_counter.c" \
        "$ROOT/src/security/mnv_outauth.c" "$ROOT/src/security/mnv_blake2s.c" \
        "$ROOT/src/security/mnv_ct.c" \
        -o "$TMP/outauth_counter" 2>"$TMP/oac.berr"; then
    echo "  BUILD FAILED"; cat "$TMP/oac.berr"; rc=1
elif ! "$TMP/outauth_counter"; then rc=1; fi
echo

# Blinded-LUT trace uniformity (Item 8): every activation, including the linear
# output layer, runs the equalizing masked scan (observed via PRNG advance).
echo "=== lut_uniform ==="
if ! $CC $FLAGS -DMNV_TARGET_HOST -DMNV_ARCH_MLP -DMNV_ENABLE_BLINDED_LUT $INC \
        "$ROOT/tests/host/test_lut_uniform.c" "$ROOT/src/security/mnv_lut.c" \
        -o "$TMP/lut_uniform" 2>"$TMP/lut.berr"; then
    echo "  BUILD FAILED"; cat "$TMP/lut.berr"; rc=1
elif ! "$TMP/lut_uniform"; then rc=1; fi
echo

# A rejected inference must invalidate the output attestation (red-team Fix 4).
run_cfg reject_clears_mac test_reject_clears_mac.c "$ROOT/src/arch/mnv_mlp.c" \
    -DMNV_TARGET_HOST -DMNV_ARCH_MLP -DMNV_MIN_CONFIDENCE=100 \
    -DMNV_INPUT_SIZE=8 -DMNV_LAYER_0_SIZE=8 -DMNV_LAYER_1_SIZE=8 \
    -DMNV_OUTPUT_SIZE=4 -DMNV_NUM_LAYERS=3

# Confidence-check threshold semantics (only needs mnv_ct.c; threshold > 0)
echo "=== confidence ==="
if ! $CC $FLAGS -DMNV_TARGET_HOST -DMNV_MIN_CONFIDENCE=20 $INC \
        "$ROOT/tests/host/test_confidence.c" "$ROOT/src/security/mnv_ct.c" \
        -o "$TMP/confidence" 2>"$TMP/confidence.berr"; then
    echo "  BUILD FAILED"; cat "$TMP/confidence.berr"; rc=1
elif ! "$TMP/confidence"; then rc=1; fi
echo

# Configurable input-range validation (F2): compile with a tightened range and
# prove out-of-band inputs (incl. the int8 extremes the default range accepts)
# are rejected. Only needs mnv_ct.c.
echo "=== input_bounds ==="
if ! $CC $FLAGS -DMNV_TARGET_HOST -DMNV_INPUT_MIN=-100 -DMNV_INPUT_MAX=100 $INC \
        "$ROOT/tests/host/test_input_bounds.c" "$ROOT/src/security/mnv_ct.c" \
        -o "$TMP/input_bounds" 2>"$TMP/ib.berr"; then
    echo "  BUILD FAILED"; cat "$TMP/ib.berr"; rc=1
elif ! "$TMP/input_bounds"; then rc=1; fi
echo

# Anti-glitch canary layout lock (R1): canaries must bracket the sensitive
# buffers. Only needs mnv_ct.c (canary plant/check) + the ctx struct.
echo "=== canary_layout ==="
if ! $CC $FLAGS -DMNV_TARGET_HOST -DMNV_ARCH_MLP $INC \
        "$ROOT/tests/host/test_canary_layout.c" "$ROOT/src/security/mnv_ct.c" \
        -o "$TMP/canary_layout" 2>"$TMP/cl.berr"; then
    echo "  BUILD FAILED"; cat "$TMP/cl.berr"; rc=1
elif ! "$TMP/canary_layout"; then rc=1; fi
echo

# Compiler-emit smoke tests — run the real minerva_compile.py end to end and
# compile + check its emitted weights.c against a Python reference (MLP and
# CNN1D paths). Skip cleanly if python3/numpy are unavailable.
if ! bash "$ROOT/tests/host/test_compiler_emit.sh";     then rc=1; fi
echo
if ! bash "$ROOT/tests/host/test_compiler_emit_cnn.sh"; then rc=1; fi
echo
# CNN1D quantization accuracy: calibrated dense shift vs heuristic (H4).
if ! bash "$ROOT/tests/host/test_cnn_accuracy.sh"; then rc=1; fi
echo

if [ "$rc" -eq 0 ]; then echo "ALL ENGINE CONFIGS PASSED"; else echo "ENGINE TESTS FAILED"; fi
exit $rc
