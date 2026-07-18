#!/usr/bin/env bash
#
# Constant-time branch audit for AVR (H2).
#
# WHY AVR-ONLY: on hosts, clang/gcc canonicalize BOTH a branchless mask idiom
# (v & ~m)|(c & m) AND a plain `if` into a conditional-select (csel/cmov) at -O2
# — so a host disassembly cannot distinguish "branchless" from "branchy" source,
# and a host branch audit is vacuous. The distinction only appears on a target
# with NO conditional-move instruction, where the mask idiom stays branchless
# but `if` becomes a real data-dependent branch. AVR is exactly that target (and
# the one the constant-time work in this library is for). So this audit compiles
# with avr-gcc and asserts the straight-line CT helpers contain no br<cc>.
#
# If the AVR toolchain is absent it SKIPS (host CT timing is covered separately
# by test_ct_timing.c). Meaningful in a CI that has avr-gcc/avr-objdump.
#
# Usage: tests/host/check_ct_branches.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AVR_CC="${AVR_CC:-avr-gcc}"
AVR_OBJDUMP="${AVR_OBJDUMP:-avr-objdump}"

if ! command -v "$AVR_CC" >/dev/null 2>&1 || ! command -v "$AVR_OBJDUMP" >/dev/null 2>&1; then
    echo "=== ct_branches === SKIP (no avr-gcc/avr-objdump; a host audit is vacuous — see header)"
    exit 0
fi

echo "=== ct_branches (avr-gcc) ==="
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! "$AVR_CC" -std=c11 -Os -mmcu=atmega328p -c -DMNV_TARGET_ATMEGA328P \
        -I"$ROOT/include" -I"$ROOT/src/core" -I"$ROOT/src/security" -I"$ROOT/src/arch" -I"$ROOT/src/hal" \
        "$ROOT/src/core/mnv_fixed.c" -o "$TMP/fixed.o" 2>"$TMP/cc.err"; then
    echo "  BUILD FAILED"; cat "$TMP/cc.err"; exit 1
fi
"$AVR_OBJDUMP" -d "$TMP/fixed.o" > "$TMP/dis.txt"

# All AVR conditional branches are br<cc> (brne, breq, brlo, brsh, brmi, brpl,
# brge, brlt, brcc, brcs, brts, brtc, brvs, brvc, brhs, brhc, brie, brid, ...).
# rjmp/jmp/ijmp (unconditional), rcall/call, ret are allowed.
COND_RE='(^|[[:space:]])br(cc|cs|eq|ne|sh|lo|mi|pl|ge|lt|hs|hc|ts|tc|vs|vc|ie|id|bs|bc)([[:space:]]|$)'

# mnv_q8_clamp inlines into these loop-free callers; auditing them audits the
# inlined branchless clamp. All four are straight-line (no data-independent loop
# either, so ANY br<cc> here is a data-dependent branch).
rc=0; audited=0
for fn in mnv_q8_mul mnv_q8_add_bias_clamp mnv_act_relu mnv_act_sign; do
    awk -v f="$fn" '
        $0 ~ ("<" f ">:") { inx = 1; next }
        inx && /^[0-9a-f]+ <.*>:/ { inx = 0 }
        inx { print }
    ' "$TMP/dis.txt" > "$TMP/body.txt"
    if [ ! -s "$TMP/body.txt" ]; then echo "  $fn: not a standalone symbol (inlined) — skip"; continue; fi
    audited=$((audited+1))
    n=$(grep -aEc "$COND_RE" "$TMP/body.txt" || true)
    if [ "$n" -eq 0 ]; then
        echo "  $fn: 0 conditional branches  PASS"
    else
        echo "  $fn: $n conditional branch(es)  FAIL"
        grep -aE "$COND_RE" "$TMP/body.txt" | sed 's/^/      /'
        rc=1
    fi
done
[ "$audited" -eq 0 ] && echo "  (all target functions inlined away; nothing audited)"

if [ "$rc" -eq 0 ]; then echo "CT BRANCH AUDIT PASSED"; else echo "CT BRANCH AUDIT FAILED"; fi
exit $rc
