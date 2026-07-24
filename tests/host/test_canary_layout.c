/**
 * @file test_canary_layout.c
 * @brief Lock the anti-glitch canary layout: canary_pre and canary_post must
 *        BRACKET the sensitive buffer region (activation ping-pong, weight
 *        scratch, double-run buffer, ChaCha keystream), not sit together
 *        elsewhere. Earlier both arrays lived after the whole struct, bracketing
 *        nothing, so a localized upset of the buffers could pass the check while
 *        the README diagram implied bracketing. This regression fails if a
 *        future field reorder breaks the bracket.
 *
 * Also checks the functional contract: a corrupted canary (either end) is
 * detected as MNV_ERR_GLITCH.
 *
 * Build: see tests/host/run_engine_tests.sh (canary_layout config).
 */

#ifndef MNV_TARGET_HOST      /* may be passed via -D */
#define MNV_TARGET_HOST
#endif
#include "minerva.h"
#include "mnv_ct.h"
#include <stddef.h>
#include <stdio.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    int _ok = (cond); \
    printf("  %-56s %s\n", (msg), _ok ? "PASS" : "FAIL"); \
    if (!_ok) fails++; } while (0)

#define OFF(f) offsetof(mnv_ctx_t, f)

int main(void) {
    printf("[canary layout: canaries must bracket the sensitive buffers]\n");

    /* Bracket boundaries. */
    CHECK(OFF(canary_pre)  < OFF(buf_a),        "canary_pre before the buffer region");
    CHECK(OFF(canary_post) > OFF(chacha_block), "canary_post after the last sensitive buffer");

    /* Every sensitive buffer sits strictly inside [canary_pre, canary_post]. */
    CHECK(OFF(canary_pre) < OFF(buf_a)          && OFF(buf_a)          < OFF(canary_post), "buf_a bracketed");
    CHECK(OFF(canary_pre) < OFF(buf_b)          && OFF(buf_b)          < OFF(canary_post), "buf_b bracketed");
    CHECK(OFF(canary_pre) < OFF(weight_scratch) && OFF(weight_scratch) < OFF(canary_post), "weight_scratch bracketed");
    CHECK(OFF(canary_pre) < OFF(run2_buf)       && OFF(run2_buf)       < OFF(canary_post), "run2_buf bracketed");
    CHECK(OFF(canary_pre) < OFF(chacha_block)   && OFF(chacha_block)   < OFF(canary_post), "chacha_block bracketed");

    /* Non-sensitive session state is OUTSIDE the bracket (must not be zeroed by a
     * per-inference wipe, and needn't be canary-protected). */
    CHECK(OFF(output_mac)        > OFF(canary_post), "output_mac outside bracket");
    CHECK(OFF(inference_counter) > OFF(canary_post), "inference_counter outside bracket");

    /* Functional: a corrupted canary at either end is detected. */
    static mnv_ctx_t c;
    mnv_canary_plant(&c);
    CHECK(mnv_canary_check(&c) == MNV_OK, "freshly planted canaries -> OK");
    c.canary_pre[0] ^= 0x1u;
    CHECK(mnv_canary_check(&c) == MNV_ERR_GLITCH, "corrupt canary_pre -> GLITCH");
    c.canary_pre[0] ^= 0x1u;
    c.canary_post[MNV_CANARY_COUNT - 1u] ^= 0x80000000u;
    CHECK(mnv_canary_check(&c) == MNV_ERR_GLITCH, "corrupt canary_post -> GLITCH");

    printf("%s (%d failure[s])\n", fails ? "FAILED" : "ALL PASS", fails);
    return fails;
}
