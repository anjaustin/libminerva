# MINERVA

| Category | Badges |
|---|---|
| **Release** | ![Version](https://img.shields.io/badge/version-1.3.0-blue) ![Codename](https://img.shields.io/badge/codename-Athena-gold) |
| **Core** | ![Language](https://img.shields.io/badge/language-C-00599C) ![Standard](https://img.shields.io/badge/C-C11-blue) ![License](https://img.shields.io/badge/license-MIT-green) |
| **Quality** | ![Build](https://img.shields.io/badge/build-passing-brightgreen) ![Tests](https://img.shields.io/badge/tests-passing-brightgreen) |
| **Embedded Constraints** | ![Allocation](https://img.shields.io/badge/allocation-zero-orange) ![Dynamic Memory](https://img.shields.io/badge/dynamic%20memory-none-red) |
| **Security** | ![Security](https://img.shields.io/badge/security-encrypted%20%7C%20authenticated-purple) ![Crypto](https://img.shields.io/badge/crypto-ChaCha20%20%2B%20BLAKE2s-purple) |
| **Hardware Targets** | ![Targets](https://img.shields.io/badge/targets-AVR%20%7C%20STM32%20%7C%20Host-lightgrey) ![MCU](https://img.shields.io/badge/min%20target-ATmega328P-informational) |
| **Footprint** | ![RAM](https://img.shields.io/badge/RAM-~960B-informational) ![Flash](https://img.shields.io/badge/flash-~14KB-informational) |

<img width="2349" height="758" alt="image" src="https://github.com/user-attachments/assets/efc12c71-9c4c-42d3-a6c9-70d513156137" />



**Minimal Inference Engine for Robust, Verifiable, and Authenticated ML**
*Version 1.3.0 - "Athena"*

```
Small. Secure. Certain.
```

Minerva is a pure C ML inference library for microcontrollers, from ATtiny85 to
STM32, with military-grade security properties. It runs encrypted,
integrity-verified neural networks with constant-time execution, anti-glitch
canaries, blinded LUT activations, output authentication, and zero dynamic
allocation.

The smallest supported target is an **ATmega328P** (32 KB flash, 2 KB RAM).
A 3-layer MLP runs in ~14.5 KB flash at ~28 ms/inference including all
security overhead.

---

## The Three Minerva Laws

> **I. Certainty** - Minerva never produces output from an unverified model.
> Integrity checking is not optional.

> **II. Silence** - Minerva reveals nothing about weights, activations, or
> intermediate state through timing, power, or output behavior.

> **III. Stillness** - Minerva never allocates dynamically. Every byte it will
> ever use is known at compile time.

---

## Features

| Feature | Details |
|---|---|
| **Architectures** | MLP, 1D CNN, Binary Neural Network (BNN) |
| **Quantization** | Q8 (int8), Q4, Binary (1-bit XNOR+popcount) |
| **Weight encryption** | ChaCha20-256, RFC 7539, constant-time |
| **Integrity** | BLAKE2s-256 keyed MAC, encrypt-then-MAC |
| **Accumulator** | int32_t throughout -- no overflow for any layer width |
| **Anti-glitch** | SRAM canaries + double-run comparison |
| **Blinded LUT** | Offset-masked activation scan, Law II hardening (v1.1) |
| **Output auth** | Per-inference session MAC, replay prevention (v1.1) |
| **Allocation** | Zero. Static buffers only. |
| **Targets** | ATtiny85, ATmega328P, ATmega2560, STM32F0/F4, Host |
| **Compiler** | Python: float model to encrypted C arrays + debug dump |

---

## Quick Start

### 1. Configure

Pick your target, architecture, and quantization in `include/mnv_config.h`:

```c
#define MNV_TARGET_ATMEGA328P
#define MNV_ARCH_MLP
#define MNV_QUANT_Q8
```

You do **not** need to hand-write the model topology. The compiler (step 2)
emits `mnv_model_dims.h`; as long as that file's directory is on the include
path of **every** translation unit (add `-I.` — see the example Makefile),
`mnv_config.h` adopts the topology automatically, so the engine objects and
your application are sized identically. `mnv_init()` also rejects a model whose
shape disagrees with the compiled-in buffer sizes (`MNV_ERR_CONFIG`), so a
misconfigured build fails loudly instead of corrupting SRAM. Hand-defining the
`MNV_*_SIZE` macros (or `-D` flags) still works and overrides the generated
header.

### 2. Compile model

```bash
# One-time: generate device key
python compiler/minerva_compile.py --gen-key key.bin

# Compile trained model
python compiler/minerva_compile.py model.npz \
    --key key.bin --target atmega328p --quant q8

# Optional: dump decrypted weights for Python-side validation
python compiler/minerva_compile.py model.npz \
    --key key.bin --target atmega328p --dump-weights
```

### 3. Use in firmware

```c
#include "minerva.h"
#include "weights.h"   // generated
#include "secrets.h"   // defines MNV_DEVICE_KEY

static mnv_ctx_t ctx;

void setup(void) {
    if (mnv_init(&ctx, &mnv_model) != MNV_OK) fatal();
    mnv_seed_prng(&ctx, read_adc_noise()); // hardware entropy
}

void loop(void) {
    int8_t input[MNV_INPUT_SIZE]   = { /* sensor data */ };
    int8_t output[MNV_OUTPUT_SIZE] = { 0 };

    if (mnv_run_with_model(&ctx, &mnv_model, input, output) == MNV_OK) {
        uint8_t cls = mnv_ct_argmax(output, MNV_OUTPUT_SIZE);
        act_on_class(cls);
    }
}
```

---

## Resource Budget

**Target:** ATmega328P, **Model:** MLP 8->16->8->4, Q8

| Resource | v1.1 | v1.2 | Budget |
|---|---|---|---|
| Flash | 14,438 B | 14,494 B | 32,768 B |
| SRAM | 1,442 B | 1,488 B | 2,048 B |
| Inference time | ~26 ms | ~28 ms | -- |
| Flash delta | -- | +56 B | int32 accumulator |

The +56 B flash and +2 ms for int32 accumulator is the correct engineering
tradeoff: int16 overflows for any layer with more than 2 inputs.

---

## What Changed in v1.2

### Bug 1 -- BLAKE2s rotation direction (critical, security)
BLAKE2s uses ROTATE RIGHT in its G mixing function. v1.0/v1.1 used ROTATE
LEFT for the 12, 8, and 7-bit rotations. This caused every MAC verification
to fail, meaning tampered models were accepted and legitimate models were
rejected. Fixed with ROTR32 macro.

**Impact:** MAC verification was completely broken in v1.0 and v1.1.

### Bug 2 -- int16 accumulator overflow (critical, correctness)
The Q8 dot product accumulator was `int16_t`. For any layer with 3 or more
inputs, `N * 127 * 127 > 32767` overflows int16. For typical networks
(8+ inputs per layer), results were completely wrong.

Fixed: `mnv_acc_t` is now `int32_t` throughout. Cost: +56 B flash, +2 ms
inference on ATmega328P.

### Bug 3 -- Weight matrix transpose (critical, correctness)
The Python compiler serialized weights as `W[in, out]` row-major, but the C
engine indexes them as `W[out, in]` (weight[out_neuron * in_sz + in_neuron]).
Every inference produced wrong outputs.

Fixed: compiler now transposes before serialization: `quantize(W.T)`.

### Bug 4 -- CT argmax broken (correctness)
The branchless select in `mnv_ct_argmax` used incorrect sign-bit extraction
that always returned index 0 for typical input vectors.

Fixed: rewrote with `diff16 = (int16_t)vec[i] - (int16_t)max_val` and
`is_gt = ~((uint8_t)((uint16_t)(diff16-1) >> 8))`.

### Bug 5 -- MNV_MIN_CONFIDENCE default too aggressive
Default of 64 (25% of Q8 range) rejected valid inferences from models with
small-magnitude output logits.

Fixed: default changed to 0 (disabled). Set per-application via
`-DMNV_MIN_CONFIDENCE=N` or in `mnv_config.h`.

---

## What Changed in v1.3

A full audit and remediation pass. Highlights:

- **Build (host)** — the CMake flow now compiles and `ctest` passes; the
  include paths and source list were previously incomplete.
- **Public API** — `mnv_run_with_model`, `mnv_verify_output`, and
  `mnv_verify_output_with_key` are now declared in `minerva.h`. `mnv_run()`
  is a real entry point that runs the model bound at `mnv_init()` (no longer
  a stub).
- **Verification binding (security)** — `mnv_init()` binds the verified model
  to the context, and inference rejects any other model pointer
  (`MNV_ERR_CONFIG`). This closes a path where a context verified for one
  model could run a different, unverified one.
- **BNN** — fixed multi-layer ciphertext offset tracking, added per-layer
  bias handling, and replaced the byte-popcount dot product with a
  bit-addressed one that is correct for non-multiple-of-8 layer widths.
  `MNV_QUANT_BINARY`/`Q4`/`Q15` are now actually selectable (Q8 no longer
  forced on).
- **Buffer sizing** — activation, weight-scratch, and bias buffers are sized
  to the widest layer, not layer 0 (previously overflowed when a hidden layer
  was wider than the input).
- **Confidence check** — signed comparison (a negative max logit is low
  confidence, not high) and its own `MNV_ENABLE_CONFIDENCE_CHECK` flag.
- **Compiler** — PTQ calibration (`--calibrate`) for better bias scaling.
- **Tests** — added end-to-end engine tests (MLP / CNN1D / BNN) that check
  output against an independent reference, run under ASan + UBSan.
- **Project** — added `LICENSE` (MIT) and `.gitignore`.

---

## Post-1.3 Audit Remediation (v1.3.1)

A second audit pass, remediated item by item with an adversarial red-team and
a regression test for each fix.

- **Compiler codegen (critical)** — `minerva_compile.py` emitted `}},` (a
  doubled closing brace) for every layer descriptor, so *every* generated
  `weights.c` failed to compile — the entire documented model-production path
  was broken. Fixed. Added `tests/host/test_compiler_emit.sh`, a smoke test
  that runs the real compiler end to end, compiles its emitted C against the
  engine, and checks every output against an independent Python Q8 reference.
  Wired into the `minerva_engine_tests` target (skips cleanly without
  python3/numpy).
- **Topology propagation (high)** — the engine translation units only ever saw
  the `mnv_config.h` *default* topology, never the compiled model's, so unless
  you hand-edited `mnv_config.h` the engine and application disagreed on
  `mnv_ctx_t` size and buffer bounds (an out-of-bounds read of `input`). The
  compiler now emits a pure-macro `mnv_model_dims.h`; `mnv_config.h` adopts it
  via `__has_include`, so all TUs converge with zero manual config. Added a
  runtime topology guard in `mnv_init()` as a defense-in-depth backstop
  (`MNV_ERR_CONFIG` on mismatch) and the example Makefile now passes `-I.`.
- **Public `mnv_ct_argmax` (medium)** — the quick-start consumes the output
  with `mnv_ct_argmax()`, but it was declared only in the internal
  `mnv_ct.h`, so the documented snippet didn't compile. It's now in
  `minerva.h`, documented (constant-time, lowest index wins on ties) and
  verified against a reference over 200k random vectors.
- **64 KB model ceiling (medium)** — `encrypted_len` and the BLAKE2s/ChaCha20
  length parameters were `uint16_t`, silently truncating any model over 64 KB
  (the advertised STM32F4 ~800K-param target needs far more). The whole blob-
  length path is now `uint32_t`, so flat-memory targets (STM32, host) handle
  large models correctly; a regression test runs a ~69 KB MLP end to end. On
  AVR (16-bit near flash pointers) `mnv_init()` now rejects a >64 KB blob with
  `MNV_ERR_CONFIG` instead of wrapping (see Supported Targets †).
- **Target selection precedence (surfaced during remediation)** — the hard
  `#define MNV_TARGET_ATMEGA328P` in `mnv_config.h` was unconditional, so
  `-DMNV_TARGET_HOST` (and every other `-D` target) was silently ignored and
  host builds ran under ATmega constraints. The default is now guarded so an
  explicit command-line target wins; ATmega328P remains the default when none
  is given.
- **Q15 byte-length confusion (medium)** — under Q15 `mnv_act_t` is 2 bytes, but
  the double-run compare, the output/scratch zeroing, and (security-relevant)
  the output-MAC buffer treated `MNV_*_SIZE` element counts as byte counts, so
  the upper byte of every Q15 element sat outside the MAC and could be tampered
  undetected. Added an `MNV_ACT_BYTES(n)` helper and switched all byte-oriented
  vector operations to it. Regression test flips the high byte of a Q15
  output/input element and confirms the MAC now catches it (verified it is
  missed pre-fix). Note: full Q15 *forward-pass arithmetic* (the dot product
  still narrows to int8 internally) remains future work — this fix is the
  byte-length/authentication correctness, which applies whenever Q15 is used.
- **CNN1D compiler path (low)** — the 1D-CNN architecture shipped in the engine
  but had no compiler, and `mnv_cnn1d.c` referenced a non-existent
  `compile_cnn1d.py`, so CNN1D models could only be hand-authored in C.
  `minerva_compile.py` now compiles a 1D-CNN when the `.npz` contains a
  `conv_w` key, emitting the exact `[kernels][conv_bias][dense_Wᵀ][dense_bias]`
  blob the engine reads (num_layers = 0, shape from `mnv_model_dims.h`). npz
  schema: `conv_w [F,K]`, `conv_b [F]`, `dense_w [FLAT,OUT]`, `dense_b [OUT]`,
  scalars `input_len`, `pool_size`. Build with `-DMNV_ARCH_CNN1D -I<out>`. A
  compiler-emit test quantizes the float model independently (its own
  transpose) and checks the engine output matches — verified it catches a
  wrong transpose and a wrong section order. The dense right-shift is a
  heuristic (`ceil(log2(FLAT))+7`); calibration is future work.

---

## Python Validation Note

When simulating Q8 inference in Python, use `//128` for the accumulator
right-shift, NOT `>>7`. Python's `>>` on arbitrary-precision integers does
not match C's arithmetic right shift on `int32_t` for negative values in all
cases. The compiler's `--dump-weights` flag emits `weights_debug.npz` with
the exact quantized arrays for validation:

```python
import numpy as np

d = np.load("weights_debug.npz")
W0T_q, b0_q = d["W0T_q"], d["b0_q"]

x  = input_q8.astype(np.int32)
h0 = np.maximum(0, np.clip(
    (W0T_q.astype(np.int32) @ x) // 128 + b0_q.astype(np.int32),
    -128, 127)).astype(np.int32)
# ... continue for each layer
```

---

## Stress Test Results (simavr, ATmega328P @ 16 MHz)

Model: 8->16->8->4 MLP, Q8, 4-class sensor classification, 99.2% float accuracy.

```
Init: verifying MAC... OK          <- Bug 1 fixed (was FAILED in v1.0/v1.1)
SCORE: 8/16                        <- Q8 model accuracy (not a Minerva bug)
Re-verify MAC: OK
avg inference: 27,883 us
max inference: 27,905 us
Flash: 14,494 B / 32,768 B (44.2%)
SRAM:   1,488 B /  2,048 B (72.7%)
```

The 8/16 Q8 accuracy reflects quantization degradation on class boundaries,
not a Minerva engine bug. Python Q8 simulation agrees with firmware 16/16,
confirming the engine computes correctly. See Known Limitations.

---

## Known Limitations

**Bias quantization scale**
Without calibration, biases are quantized independently (scaled to
[-127,127]), which can distort the output layer when one class has a much
larger bias than others. v1.3 adds PTQ calibration (`--calibrate`) that
scales biases to match the accumulator domain. Full quantization-aware
training (QAT) is still future work.

**SRAM scratch buffer**
The weight/activation scratch is sized to the widest layer across the whole
network (v1.3 fixed an earlier assumption that layer 0 was widest). For
models with large intermediate layers this can still push SRAM usage high;
layer-by-layer streaming with smaller scratch is planned.

**Output bus integrity**
The output MAC (v1.1) covers the result but does not encrypt it. A consumer
on the output bus can read the plaintext inference result. Encrypted output
channels are planned.

---

## Security Architecture

```
Flash (read-protected)
+-------------------------------------------------------+
|  [IV 12B] [BLAKE2s MAC 32B] [ChaCha20 ciphertext]    |
+-------------------------------------------------------+
         | mnv_init(): BLAKE2s verify -- halt on failure
         | mnv_run():  decrypt one layer at a time

SRAM (volatile)
+-------------------------------------------------------+
|  [canary x4] [act_buf_a] [act_buf_b] [weight_scratch] |
|  [canary x4]   <- zeroed after each layer             |
+-------------------------------------------------------+
         | double-run comparison on every inference
         | blinded LUT: 256-entry scan per activation

Output (v1.1+)
+-------------------------------------------------------+
|  output[0..N] + BLAKE2s-8B(output || input || counter)|
+-------------------------------------------------------+
```

---

## Running Host Tests

```bash
cmake -S . -B build -DMNV_TARGET=host && cmake --build build && ctest --test-dir build -V
```

This runs two suites: `minerva_host_tests` (32 crypto/primitive unit tests)
and `minerva_engine_tests` (end-to-end MLP / CNN1D / BNN inference checked
against an independent reference, built under ASan + UBSan).

To run just the primitive suite directly:

```bash
gcc -DMNV_TARGET_HOST -Iinclude -Isrc/core -Isrc/security -Isrc/arch -Isrc/hal \
    tests/host/test_host.c src/core/mnv_fixed.c \
    src/security/mnv_chacha20.c src/security/mnv_blake2s.c \
    src/security/mnv_ct.c src/security/mnv_lut.c \
    src/security/mnv_outauth.c src/hal/mnv_hal_host.c \
    -std=c11 -O2 -o test_host && ./test_host
# Expected: All 32 tests PASSED.

# End-to-end engine tests (all architectures):
bash tests/host/run_engine_tests.sh
```

---

## Supported Targets

| MCU | Flash | RAM | Max Params (Q8) | Status |
|---|---|---|---|---|
| ATtiny85 | 8 KB | 512 B | ~2K (BNN only) | ✓ |
| ATmega328P | 32 KB | 2 KB | ~14K | ✓ |
| ATmega2560 | 256 KB | 8 KB | ~200K † | ✓ |
| STM32F0 | 64 KB | 8 KB | ~40K | ✓ |
| STM32F4 | 1 MB | 192 KB | ~800K | ✓ |

**† AVR 64 KB blob limit.** AVR reads flash weights through 16-bit near
pointers (`pgm_read_byte`), so a single encrypted weight blob must fit in the
low 64 KB of flash. `mnv_init()` rejects a larger blob on AVR with
`MNV_ERR_CONFIG` rather than wrapping the address. The flat-memory targets
(STM32F0/F4, host) have no such limit — the blob length is a full 32-bit
value throughout. Models above 64 KB on ATmega2560 (which spans multiple flash
banks) need far-pointer access (`pgm_read_byte_far` + `RAMPZ`), which is not
yet implemented; split such models or use an STM32 target.

---

## Citation

```bibtex
@software{minerva2025,
  title   = {MINERVA: Minimal Inference Engine for Robust, Verifiable,
             and Authenticated ML},
  version = {1.3.0},
  year    = {2025},
  note    = {https://github.com/kavishka-dot/libminerva}
}
```

---

## License

MIT License. See `LICENSE`.

---

*"Inference is only useful when the model can be trusted."*
