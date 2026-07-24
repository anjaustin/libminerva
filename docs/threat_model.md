# Minerva Threat Model

**Version:** 1.0.0-McGonagall  
**Status:** Normative

> **Update (v1.1–v1.3):** mitigations marked "planned v1.1" below have since
> shipped — input-blinded LUT access (§4.3) and output authentication (§4.6).
> The confidence-threshold default changed to 0/disabled (§4.5). See the
> security-properties table in §5 for current status.

---

## 1. Scope

This document defines the threat model for Minerva ML inference on microcontrollers. It describes the assets being protected, the adversary model, the attack surface, and the mitigations implemented in v1.0.

---

## 2. Assets

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Model weights | Critical | Critical | High |
| Inference result | — | Critical | High |
| Device key | Critical | Critical | — |
| Input sensor data | Context-dependent | High | — |
| Intermediate activations | High | High | — |

**Model weights** are the primary IP asset. Disclosure allows model extraction and replication. Modification allows the adversary to control inference behavior.

**Inference result** integrity is critical in autonomous decision contexts (access control, anomaly detection, actuation).

**Device key** compromise breaks all cryptographic protections.

---

## 3. Adversary Model

### 3.1 Adversary Capabilities

Minerva assumes an adversary with:

- **Physical access** to the device (can connect probes, logic analyzers)
- **Flash dump capability** (ISP, JTAG, or exploit of bootloader)
- **Power and EM measurement** equipment (oscilloscope, EM probe)
- **Fault injection tools** (voltage glitcher, EM fault injector, laser)
- **Software access** to the communication interface (UART, SPI, I²C)
- **Time** (offline analysis of captured traces)

### 3.2 Adversary Goals

1. Extract model weights from flash
2. Determine model architecture and parameters
3. Craft adversarial inputs that produce desired outputs
4. Modify model to produce attacker-controlled outputs
5. Bypass integrity checks to run a tampered model
6. Recover intermediate activations via side channels

### 3.3 Out of Scope (v1.0)

- Compromise of the key provisioning process (assumed secure)
- Supply chain attacks on the MCU itself
- Attacks requiring access to the firmware compilation environment
- Multi-device key extraction (side-channel across many identical devices)
- Attacks on the training environment or training data

---

## 4. Attack Surface

### 4.1 Flash Dump → Weight Extraction

**Attack:** Adversary dumps flash via ISP or JTAG and reads weight values.

**Mitigation:** Weights are encrypted with ChaCha20-256. The key is never stored in flash — it is provisioned into a protected memory region (EEPROM with write-lock fuse on AVR, or TrustZone secure world on ARM). Without the key, the weight blob is indistinguishable from random bytes.

**Key domain separation:** the master device key is never handed to a primitive directly. Each purpose (weight encryption, weight MAC, output authentication) uses an independent 32-byte subkey derived as `BLAKE2s(key = master, message = {domain-label})` — see `src/security/mnv_kdf.h`, mirrored bit-for-bit by the compiler. This removes the encrypt-and-MAC-with-the-same-key overlap and ensures a weakness in one primitive cannot cross-contaminate another.

**Residual risk:** Key extraction via side channel during decryption (see §4.3).

---

### 4.2 Model Tampering

**Attack:** Adversary modifies the model to alter inference behavior — either the
encrypted weight blob, or the model's *structure* (layer widths, activation
functions, layer count).

**Mitigation:** A BLAKE2s-256 keyed MAC is verified during `mnv_init()` and on
every explicit `mnv_verify()` call. It is computed over **`S || ciphertext`**,
where `S` is a canonical serialization of the model structure the engine will
actually run — `version`, architecture id, `num_layers`, and each layer's
`input_size` / `output_size` / `activation` (for CNN1D, the conv core
dimensions). See `src/security/mnv_struct_auth.h`. Any modification to even one
byte of the ciphertext **or** to any structural field causes the MAC check to
fail; the device zeroes its SRAM state and returns `MNV_ERR_TAMPER`, and no
inference output is produced.

Binding the structure closes a gap present through v1.3.1: the descriptors
(`num_layers`, sizes, activations) drive inference but lived in a mutable
descriptor outside the ciphertext, so an attacker who could rewrite the flash
image could, e.g., turn a nonlinearity into identity or collapse the network
while still passing a ciphertext-only integrity check — running a structurally
different model the device reported as "verified" (a Law I violation). The
blob-format version was bumped (ABI `0x02`); a pre-`0x02` blob is rejected.

**Note:** the MAC is computed over *ciphertext* (encrypt-then-MAC scheme). This
prevents chosen-ciphertext attacks against the decryption layer. The structural
preamble `S` is plaintext (structure is public topology, not a protected asset)
but authenticated, so it cannot be altered undetected.

---

### 4.3 Side-Channel Attacks (Power/EM)

**Attack:** Adversary measures power consumption or EM emanation during inference and correlates with intermediate values to recover key material or weights.

**Mitigations:**

1. **ChaCha20** uses only ADD, XOR, ROTATE — no data-dependent table lookups. On AVR (no cache), this eliminates cache-timing attacks. Power leakage of arithmetic operations is significantly lower than S-box lookups (cf. AES).

2. **Constant-time arithmetic** throughout the inference pipeline: no data-dependent branches, no early exits, no data-dependent memory access patterns.

3. **LUT-based activations** (sigmoid, tanh) are accessed sequentially by index — the index depends on the activation value, which does leak through power. **This is a known limitation of v1.0.** Mitigation planned for v1.1: input-blinded LUT access.

4. **Weight decryption per layer**: only one layer's weights are ever in SRAM simultaneously. The decryption scratch is zeroed immediately after the forward pass through each layer, limiting the window for power analysis.

**Blinding-mask seed:** the LUT-blinding offset is drawn from an Xorshift32 PRNG.
Its default seed is now *derived from the device key* (`BLAKE2s(key, {PRNG})`),
not a public constant — so an attacker who does not hold the key cannot predict
the mask stream (previously the fixed default made every mask public, nullifying
the blinding). Seeding with hardware entropy via `mnv_seed_prng()` after
`mnv_init()` is still recommended: a static seed repeats the same mask sequence
across power cycles, which trace averaging can strip. The derived default is also
only as unique as the device key — devices sharing a factory master key share the
same default mask stream, so the per-device key recommendation in §6 applies to
the blinding as well.

**Residual risk (v1.0):** DPA against activation LUT accesses is theoretically possible with many traces. The attack complexity is high but not infeasible for a well-resourced adversary. See v1.1 roadmap.

---

### 4.4 Fault Injection (Voltage/Clock Glitching)

**Attack:** Adversary injects a fault during the MAC verification check, causing the integrity check to report success even when it fails, or skips the check entirely.

**Mitigations:**

1. **SRAM canaries**: `uint32_t` sentinel values **bracket** the sensitive buffer region (`canary_pre` before it, `canary_post` after — see the `mnv_ctx_t` field order, locked by `tests/host/test_canary_layout.c`) and are checked after every layer. A fault or overrun that corrupts SRAM in or around the buffers (common with voltage glitching) perturbs a canary and triggers `MNV_ERR_GLITCH`. (Through the B-series both canary arrays sat together after the struct, bracketing nothing; that is fixed.)

2. **Double-run comparison**: inference is executed twice and the two outputs are compared in constant time. **Honest scope:** both runs decrypt the *same* weights with the *same* key, IV, and counter (0) — they are **identical recomputations, not independent streams** (they cannot be independent: both must reproduce the same plaintext weights). The check therefore detects a **transient** single-event fault that perturbs exactly one run. A *permanent* fault (a stuck bit, or one reproduced identically in both runs) is **not** caught here — canaries (spatial corruption) and MAC re-verification (`mnv_verify`) cover other fault classes, and a hardware secure element covers the rest.

3. **Constant-time MAC comparison**: `mnv_ct_compare()` uses bitwise OR accumulation — a fault that skips one comparison byte cannot cause a false positive.

4. **HAL fatal**: on `MNV_ERR_GLITCH`, `mnv_hal_fatal()` enables the hardware watchdog with 15ms timeout and loops until reset. The device reboots rather than continuing in an undefined state.

**Residual risk:** A precisely timed fault that corrupts the counter value in `mnv_ct_compare()` before the final branch could theoretically bypass the check. This is extremely difficult in practice but not impossible. Hardware secure elements (ATECC608) eliminate this residual risk.

---

### 4.5 Adversarial Inputs

**Attack:** Adversary crafts inputs that cause the model to produce an incorrect output (misclassification).

**Mitigations:**

1. **Input range validation** (constant-time): all input values are checked against `[MNV_INPUT_MIN, MNV_INPUT_MAX]`. Out-of-range inputs are rejected with `MNV_ERR_INPUT` before any inference computation begins. **Honest scope:** these bounds default to the full quantization range, which for **Q8 is the entire int8 domain** — so the *default* check accepts every possible input and is a structural no-op for Q8 (it only constrains Q4/binary). To get a real gate on Q8, set the bounds to the application's actual sensor range (`-DMNV_INPUT_MIN=… -DMNV_INPUT_MAX=…`).

2. **Confidence threshold**: output is rejected if the maximum logit is below `MNV_MIN_CONFIDENCE` (default: 0, i.e. disabled; set per-application). The comparison is signed, so a negative maximum logit counts as low confidence. Low-confidence outputs — which adversarial inputs often produce after Q8 quantization — are rejected with `MNV_ERR_CONFIDENCE`.

**Residual risk:** Adversarial examples that remain within the valid input range and produce high-confidence wrong outputs are not detected. This is an inherent limitation of inference-time defenses. Training-time adversarial training is recommended for high-assurance deployments.

---

### 4.6 Communication Channel Attacks

**Attack:** Adversary injects or replays inference results on the output bus.

**Mitigation (shipped v1.1):** Per-inference output authentication — a session MAC over `output || input || counter` (see `mnv_outauth`), verifiable downstream via `mnv_verify_output()`. The result is authenticated but not encrypted; an output-bus reader can still observe the plaintext result (see README Known Limitations).

---

## 5. Security Properties

> **Verification note (added post-1.3).** "Design intent" below means the
> mechanism is implemented and, where possible, its *logic* is tested on host —
> it does **not** mean the property has been measured on the target hardware.
> In particular, power/EM resistance and fault-injection resistance have **not**
> been validated with a scope or a glitcher. See the README "Verification
> Status" section for exactly what is host-verified vs construction-only vs
> lab-required.

| Property | Status | Verified how | Notes |
|---|---|---|---|
| Weight confidentiality | Design intent | — | ChaCha20-256 encryption |
| Weight integrity | Host-tested | tamper→`MNV_ERR_TAMPER` | BLAKE2s-256 MAC over ciphertext |
| Model-structure integrity | Host-tested | metadata-tamper→`MNV_ERR_TAMPER` | MAC covers `S`(structure)‖ciphertext |
| Tamper detection (flash) | Host-tested | init + `mnv_verify` tests | MAC at init and on demand |
| Fault-injection **detection** | Design intent | logic runs on host | canaries + double-run; **resistance not lab-tested** |
| Constant-time arithmetic (timing) | Host-tested | dudect timing test (compare) | branchless by construction elsewhere |
| Constant-time on AVR (no cmov) | Construction | avr-gcc branch audit (not run here) | host audit is vacuous |
| Cache-timing resistance | Design intent | — | ChaCha20 (no S-box) |
| Power / EM resistance | **Goal only** | **not measured** | blinded LUT etc.; needs an oscilloscope/DPA |
| Adversarial input detection | Partial | range + confidence tests | inference-time only |
| Output authentication | Host-tested | outauth round-trip/wraparound | session MAC |

---

## 6. Key Management Recommendations

The device key (`MNV_DEVICE_KEY`) is the root of all security. Its compromise breaks all protections. It is used only as a *master* key: the engine and compiler derive independent per-purpose subkeys from it (see §4.1, "Key domain separation"), so no cryptographic primitive ever sees the master key directly.

**ATmega:** Use the AVR EEPROM with lock bits set (fuse `BOOTRST=0`, `BLB1=0`). Disable JTAG fuse. Use a unique per-device key derived from a factory master key via HKDF.

**STM32:** Use the RDP (Read-Out Protection) Level 2 option byte. Store key in backup SRAM powered by VBAT.

**Production:** Use a hardware secure element (ATECC608A, SE050) as a key store and co-processor for MAC verification. The MCU never sees the key in cleartext.

---

## 7. Compliance Notes

Minerva's security design is informed by:

- NIST SP 800-193 (Platform Firmware Resiliency Guidelines)
- ETSI EN 303 645 (Cyber Security for Consumer IoT)
- IEC 62443-4-2 (Security for Industrial Automation — Component Level)
- CHES best practices for embedded cryptographic implementations
