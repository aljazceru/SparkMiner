/*
 * SparkMiner - Pipelined SHA-256 v5 implementation (ESP32 / Xtensa LX6)
 *
 * Derived from sha256_pipelined_v3 (BitsyMiner lineage, GPL v3).
 * NOP-timed busy waits + CCOUNT auto-calibration (see .h for details).
 */

#include <Arduino.h>
#include "build_tune.h"

#if defined(CONFIG_IDF_TARGET_ESP32) && (defined(PIPE_V5) || defined(PIPE_V6) || defined(PIPE_V9))

#include "sha256_pipelined_v5.h"

#include <soc/dport_reg.h>
#include <soc/hwcrypto_reg.h>

#define SHA_START_OFFSET    0x90
#define SHA_CONTINUE_OFFSET 0x94
#define SHA_LOAD_OFFSET     0x98
#define SHA_BUSY_OFFSET     0x9C

volatile uint16_t g_v5_delays[5] = {0, 0, 0, 0, 0};
volatile bool g_v5_autocal = true;

static bool s_recalRequested = false;
void v5_force_recal(void) { s_recalRequested = true; }

/* ------------------------------------------------------------------ */
/* Calibration: run the v3-style loop (pure busy-poll) while measuring */
/* with CCOUNT how long each of the five busy-waits actually spins.    */
/* ------------------------------------------------------------------ */

#define V5_CAL_ITERS 64

static uint32_t v5_measure_iter_cycles(void)
{
    uint32_t t0, t1;
    const uint32_t n = 2000;
    asm volatile(
        "rsr.ccount %0        \n"
        "mov.n   a6, %2       \n"
        "1:                   \n"
        "addi    a6, a6, -1   \n"
        "bnez.n  a6, 1b       \n"
        "rsr.ccount %1        \n"
        : "=r"(t0), "=r"(t1)
        : "r"(n)
        : "a6");
    return (t1 - t0) / n;
}

static uint32_t v5_run_calibration(
    volatile uint32_t *sha_base,
    const uint32_t *header_swapped,
    uint32_t *nonce_ptr,
    volatile bool *mining_flag)
{
    static uint32_t cal[5]; /* cycle accumulators, zeroed below */

    DPORT_REG_SET_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_SHA);
    DPORT_REG_CLR_BIT(DPORT_PERI_RST_EN_REG, DPORT_PERI_EN_SHA | DPORT_PERI_EN_SECUREBOOT);

    cal[0] = cal[1] = cal[2] = cal[3] = cal[4] = 0;
    uint32_t nonce_before = *nonce_ptr;

    /* v3 body with rsr.ccount instrumentation around each busy-poll.
     * Register use: a2 nonce, a3/a4 scratch, a5 ctrl base, a7 ccount,
     * a8 zero. Operands: sb, IN, nonce, flag, pad2, len1, len2, cal.
     */
    asm volatile(
        "l32i.n   a2,  %[nonce], 0 \n"
        "addi     a5,  %[sb], 0x90 \n"
        "movi.n   a8,  0           \n"
        "movi     a9,  64          \n"   /* a9 = iteration count */
    "v5c_outer: \n"

        "l32i.n    a3,  %[IN],  0  \n"
        "s32i.n    a3,  %[sb],  0  \n"
        "l32i.n    a3,  %[IN],  4  \n"
        "s32i.n    a3,  %[sb],  4  \n"
        "l32i.n    a3,  %[IN],  8  \n"
        "s32i.n    a3,  %[sb],  8  \n"
        "l32i.n    a3,  %[IN], 12  \n"
        "s32i.n    a3,  %[sb], 12  \n"
        "l32i.n    a3,  %[IN], 16  \n"
        "s32i.n    a3,  %[sb], 16  \n"
        "l32i.n    a3,  %[IN], 20  \n"
        "s32i.n    a3,  %[sb], 20  \n"
        "l32i.n    a3,  %[IN], 24  \n"
        "s32i.n    a3,  %[sb], 24  \n"
        "l32i.n    a3,  %[IN], 28  \n"
        "s32i.n    a3,  %[sb], 28  \n"
        "l32i.n    a3,  %[IN], 32  \n"
        "s32i.n    a3,  %[sb], 32  \n"
        "l32i.n    a3,  %[IN], 36  \n"
        "s32i.n    a3,  %[sb], 36  \n"
        "l32i.n    a3,  %[IN], 40  \n"
        "s32i.n    a3,  %[sb], 40  \n"
        "l32i.n    a3,  %[IN], 44  \n"
        "s32i.n    a3,  %[sb], 44  \n"
        "l32i.n    a3,  %[IN], 48  \n"
        "s32i.n    a3,  %[sb], 48  \n"
        "l32i.n    a3,  %[IN], 52  \n"
        "s32i.n    a3,  %[sb], 52  \n"
        "l32i.n    a3,  %[IN], 56  \n"
        "s32i.n    a3,  %[sb], 56  \n"
        "l32i.n    a3,  %[IN], 60  \n"
        "s32i.n    a3,  %[sb], 60  \n"

        "movi.n  a3, 1             \n"
        "s32i.n  a3, a5, 0         \n"

        "l32i    a3,  %[IN], 64    \n"
        "s32i.n  a3,  %[sb],  0    \n"
        "l32i    a3,  %[IN], 68    \n"
        "s32i.n  a3,  %[sb],  4    \n"
        "l32i    a3,  %[IN], 72    \n"
        "s32i.n  a3,  %[sb],  8    \n"
        "s32i.n  a2, %[sb], 12     \n"
        "movi    a3, 0x80000000    \n"
        "s32i.n  a3,  %[sb], 16    \n"
        "s32i.n  a8,  %[sb], 20    \n"
        "s32i.n  a8,  %[sb], 24    \n"
        "s32i.n  a8,  %[sb], 28    \n"
        "s32i.n  a8,  %[sb], 32    \n"
        "s32i.n  a8,  %[sb], 36    \n"
        "s32i.n  a8,  %[sb], 40    \n"
        "s32i.n  a8,  %[sb], 44    \n"
        "s32i.n  a8,  %[sb], 48    \n"
        "s32i.n  a8,  %[sb], 52    \n"
        "s32i.n  a8,  %[sb], 56    \n"
        "movi    a3, 0x280         \n"
        "s32i.n  a3,  %[sb], 60    \n"

        "movi.n  a7, 6            \n"
    "v5c_r1: \n"
        "addi    a7, a7, -1        \n"
        "bnez.n  a7, v5c_r1       \n"
        "rsr.ccount a7            \n"
    "v5c_w1: \n"
        "l32i.n  a3, a5, 12       \n"
        "bnez.n  a3, v5c_w1       \n"
        "rsr.ccount a4            \n"
        "sub     a4, a4, a7       \n"
        "l32i.n  a3, %[cal], 0    \n"
        "add.n   a3, a3, a4       \n"
        "s32i.n  a3, %[cal], 0    \n"

        "movi.n  a3, 1            \n"
        "s32i.n  a3, a5, 4        \n"
        "memw                     \n"

        "movi.n  a7, 6            \n"
    "v5c_r2: \n"
        "addi    a7, a7, -1        \n"
        "bnez.n  a7, v5c_r2       \n"
        "rsr.ccount a7            \n"
    "v5c_w2: \n"
        "l32i.n  a4, a5, 12       \n"
        "bnez.n  a4, v5c_w2       \n"
        "rsr.ccount a3            \n"
        "sub     a3, a3, a7       \n"
        "l32i.n  a4, %[cal], 4    \n"
        "add.n   a4, a4, a3       \n"
        "s32i.n  a4, %[cal], 4    \n"

        "movi.n  a4, 1            \n"
        "s32i.n  a4, a5, 8        \n"
        "memw                     \n"

        "addi.n  a2, a2, 1        \n"

        "movi.n  a7, 6            \n"
    "v5c_r3: \n"
        "addi    a7, a7, -1        \n"
        "bnez.n  a7, v5c_r3       \n"
        "rsr.ccount a7            \n"
    "v5c_w3: \n"
        "l32i.n  a4, a5, 12       \n"
        "bnez.n  a4, v5c_w3       \n"
        "rsr.ccount a3            \n"
        "sub     a3, a3, a7       \n"
        "l32i.n  a4, %[cal], 8    \n"
        "add.n   a4, a4, a3       \n"
        "s32i.n  a4, %[cal], 8    \n"

        "movi    a3, 0x80000000    \n"
        "s32i.n  a3,  %[sb], 32    \n"
        "movi    a3, 0x100         \n"
        "s32i.n  a3,  %[sb], 60    \n"

        "movi.n  a4, 1            \n"
        "s32i.n  a4, a5, 0        \n"
        "memw                     \n"

        "movi.n  a7, 6            \n"
    "v5c_r4: \n"
        "addi    a7, a7, -1        \n"
        "bnez.n  a7, v5c_r4       \n"
        "rsr.ccount a7            \n"
    "v5c_w4: \n"
        "l32i.n  a4, a5, 12       \n"
        "bnez.n  a4, v5c_w4       \n"
        "rsr.ccount a3            \n"
        "sub     a3, a3, a7       \n"
        "l32i.n  a4, %[cal], 12   \n"
        "add.n   a4, a4, a3       \n"
        "s32i.n  a4, %[cal], 12   \n"

        "movi.n  a3, 1            \n"
        "s32i.n  a3, a5, 8        \n"
        "memw                     \n"

        "movi.n  a7, 6            \n"
    "v5c_r5: \n"
        "addi    a7, a7, -1        \n"
        "bnez.n  a7, v5c_r5       \n"
        "rsr.ccount a7            \n"
    "v5c_w5: \n"
        "l32i.n  a4, a5, 12       \n"
        "bnez.n  a4, v5c_w5       \n"
        "rsr.ccount a3            \n"
        "sub     a3, a3, a7       \n"
        "l32i.n  a4, %[cal], 16   \n"
        "add.n   a4, a4, a3       \n"
        "s32i.n  a4, %[cal], 16   \n"

        "addi.n  a9, a9, -1       \n"
        "beqz.n  a9, v5c_exit     \n"

        "l8ui   a3, %[flag], 0    \n"
        "beqz.n a3, v5c_exit      \n"

        "l16ui  a3, %[sb], 28     \n"
        "bnez.n a3, v5c_cont      \n"
        "j      v5c_exit          \n"
    "v5c_cont: \n"
        "j      v5c_outer         \n"
    "v5c_exit: \n"
        "s32i.n a2, %[nonce], 0   \n"

        :
        : [sb] "r"(sha_base),
          [IN] "r"(header_swapped),
          [nonce] "r"(nonce_ptr),
          [flag] "r"(mining_flag),
          [cal] "r"(cal)
        : "a2", "a3", "a4", "a5", "a7", "a8", "a9", "memory"
    );

    uint32_t iters = *nonce_ptr - nonce_before;
    if (iters == 0) iters = 1;
    if (iters > V5_CAL_ITERS) iters = V5_CAL_ITERS;

    uint32_t cpi = v5_measure_iter_cycles();
    if (cpi == 0) cpi = 4;

    uint32_t avg[5];
    for (int i = 0; i < 5; i++) avg[i] = cal[i] / iters;

    /* delay_iters = (write-drain allowance + residual)/itercost, minus one
     * iteration of guard so the bounded poll normally catches just the tail.
     * The residual is measured after the cal-loop's drain spin, i.e. it is the
     * engine time left once the control write has landed; the main loop has no
     * drain spin, so ~12 cycles are added to also cover the write drain. */
    uint16_t nd[5];
    for (int i = 0; i < 5; i++) {
        int32_t n = (int32_t)((avg[i] + 12) / cpi) - 1;
        if (n < 0) n = 0;
        if (n > 4000) n = 4000;
        nd[i] = (uint16_t)n;
        g_v5_delays[i] = nd[i];
    }

    Serial.printf("[V5-CAL] iters=%u cpi=%u w1=%u w2=%u w3=%u w4=%u w5=%u cyc -> n=[%u,%u,%u,%u,%u]\n",
                  iters, cpi, avg[0], avg[1], avg[2], avg[3], avg[4],
                  nd[0], nd[1], nd[2], nd[3], nd[4]);
    return iters;
}

/* ------------------------------------------------------------------ */
/* Main v5 mining loop                                                 */
/* ------------------------------------------------------------------ */

bool IRAM_ATTR sha256_pipelined_mine_v5(
    volatile uint32_t *sha_base,
    const uint32_t *header_swapped,
    uint32_t *nonce_ptr,
    volatile uint64_t *hash_count_ptr,
    volatile bool *mining_flag)
{
    DPORT_REG_SET_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_SHA);
    DPORT_REG_CLR_BIT(DPORT_PERI_RST_EN_REG, DPORT_PERI_EN_SHA | DPORT_PERI_EN_SECUREBOOT);

    static bool s_calibrated = false;
    if (g_v5_autocal && (!s_calibrated || s_recalRequested)) {
        s_recalRequested = false;
        v5_run_calibration(sha_base, header_swapped, nonce_ptr, mining_flag);
        s_calibrated = true;
    }

    /*
     * Register allocation (mirrors v3):
     *   a2 = nonce, a3/a4 = scratch, a5 = control base (sb+0x90),
     *   a6 = delay counter, a8 = zero
     * Delay loads: l16ui a6, %[nd], {0,2,4,6,8} then bounded poll.
     */
    asm volatile(
        "l32i.n   a2,  %[nonce], 0 \n"
        "addi     a5,  %[sb], 0x90 \n"
        "movi.n   a8,  0           \n"

    "v5_start: \n"

        "l32i.n    a3,  %[IN],  0  \n"
        "s32i.n    a3,  %[sb],  0  \n"
        "l32i.n    a3,  %[IN],  4  \n"
        "s32i.n    a3,  %[sb],  4  \n"
        "l32i.n    a3,  %[IN],  8  \n"
        "s32i.n    a3,  %[sb],  8  \n"
        "l32i.n    a3,  %[IN], 12  \n"
        "s32i.n    a3,  %[sb], 12  \n"
        "l32i.n    a3,  %[IN], 16  \n"
        "s32i.n    a3,  %[sb], 16  \n"
        "l32i.n    a3,  %[IN], 20  \n"
        "s32i.n    a3,  %[sb], 20  \n"
        "l32i.n    a3,  %[IN], 24  \n"
        "s32i.n    a3,  %[sb], 24  \n"
        "l32i.n    a3,  %[IN], 28  \n"
        "s32i.n    a3,  %[sb], 28  \n"
        "l32i.n    a3,  %[IN], 32  \n"
        "s32i.n    a3,  %[sb], 32  \n"
        "l32i.n    a3,  %[IN], 36  \n"
        "s32i.n    a3,  %[sb], 36  \n"
        "l32i.n    a3,  %[IN], 40  \n"
        "s32i.n    a3,  %[sb], 40  \n"
        "l32i.n    a3,  %[IN], 44  \n"
        "s32i.n    a3,  %[sb], 44  \n"
        "l32i.n    a3,  %[IN], 48  \n"
        "s32i.n    a3,  %[sb], 48  \n"
        "l32i.n    a3,  %[IN], 52  \n"
        "s32i.n    a3,  %[sb], 52  \n"
        "l32i.n    a3,  %[IN], 56  \n"
        "s32i.n    a3,  %[sb], 56  \n"
        "l32i.n    a3,  %[IN], 60  \n"
        "s32i.n    a3,  %[sb], 60  \n"

        "movi.n  a3, 1             \n"
        "s32i.n  a3, a5, 0         \n"

        "l32i    a3,  %[IN], 64    \n"
        "s32i.n  a3,  %[sb],  0    \n"
        "l32i    a3,  %[IN], 68    \n"
        "s32i.n  a3,  %[sb],  4    \n"
        "l32i    a3,  %[IN], 72    \n"
        "s32i.n  a3,  %[sb],  8    \n"
        "s32i.n  a2, %[sb], 12     \n"
        "movi    a3, 0x80000000    \n"
        "s32i.n  a3,  %[sb], 16    \n"
        "s32i.n  a8,  %[sb], 20    \n"
        "s32i.n  a8,  %[sb], 24    \n"
        "s32i.n  a8,  %[sb], 28    \n"
        "s32i.n  a8,  %[sb], 32    \n"
        "s32i.n  a8,  %[sb], 36    \n"
        "s32i.n  a8,  %[sb], 40    \n"
        "s32i.n  a8,  %[sb], 44    \n"
        "s32i.n  a8,  %[sb], 48    \n"
        "s32i.n  a8,  %[sb], 52    \n"
        "s32i.n  a8,  %[sb], 56    \n"
        "movi    a3, 0x280         \n"
        "s32i.n  a3,  %[sb], 60    \n"

        /* w1: tuned delay then bounded poll */
        "l16ui   a6, %[nd], 0      \n"
        "beqz.n  a6, v5_p1         \n"
    "v5_d1: \n"
        "addi    a6, a6, -1        \n"
        "bnez.n  a6, v5_d1         \n"
    "v5_p1: \n"
        "l32i.n  a3, a5, 12        \n"
        "bnez.n  a3, v5_p1         \n"

        "movi.n  a3, 1             \n"
        "s32i.n  a3, a5, 4         \n"

        /* w2 */
        "l16ui   a6, %[nd], 2      \n"
        "beqz.n  a6, v5_p2         \n"
    "v5_d2: \n"
        "addi    a6, a6, -1        \n"
        "bnez.n  a6, v5_d2         \n"
    "v5_p2: \n"
        "l32i.n  a4, a5, 12        \n"
        "bnez.n  a4, v5_p2         \n"

        "movi.n  a4, 1             \n"
        "s32i.n  a4, a5, 8         \n"

        "addi.n  a2, a2, 1         \n"

        /* w3 (LOAD) */
        "l16ui   a6, %[nd], 4      \n"
        "beqz.n  a6, v5_p3         \n"
    "v5_d3: \n"
        "addi    a6, a6, -1        \n"
        "bnez.n  a6, v5_d3         \n"
    "v5_p3: \n"
        "l32i.n  a4, a5, 12        \n"
        "bnez.n  a4, v5_p3         \n"

        "movi    a3, 0x80000000    \n"
        "s32i.n  a3,  %[sb], 32    \n"
        "movi    a3, 0x100         \n"
        "s32i.n  a3,  %[sb], 60    \n"

        "movi.n  a4, 1             \n"
        "s32i.n  a4, a5, 0         \n"

        "l32i.n  a3, %[ih], 0      \n"
        "addi.n  a3, a3, 1         \n"
        "s32i.n  a3, %[ih], 0      \n"
        "bnez.n  a3, v5_no_carry   \n"
        "l32i.n  a4, %[ih], 4      \n"
        "addi.n  a4, a4, 1         \n"
        "s32i.n  a4, %[ih], 4      \n"
    "v5_no_carry: \n"

        /* w4 */
        "l16ui   a6, %[nd], 6      \n"
        "beqz.n  a6, v5_p4         \n"
    "v5_d4: \n"
        "addi    a6, a6, -1        \n"
        "bnez.n  a6, v5_d4         \n"
    "v5_p4: \n"
        "l32i.n  a4, a5, 12        \n"
        "bnez.n  a4, v5_p4         \n"

        "movi.n  a3, 1             \n"
        "s32i.n  a3, a5, 8         \n"

        /* w5 (LOAD) */
        "l16ui   a6, %[nd], 8      \n"
        "beqz.n  a6, v5_p5         \n"
    "v5_d5: \n"
        "addi    a6, a6, -1        \n"
        "bnez.n  a6, v5_d5         \n"
    "v5_p5: \n"
        "l32i.n  a4, a5, 12        \n"
        "bnez.n  a4, v5_p5         \n"

        "l8ui   a3, %[flag], 0     \n"
        "beqz.n a3, v5_end         \n"

        "l16ui  a3, %[sb], 28      \n"
        "beqz.n a3, v5_end         \n"

        "j v5_start                \n"

    "v5_end: \n"
        "s32i.n a2, %[nonce], 0    \n"

        :
        : [sb] "r"(sha_base),
          [IN] "r"(header_swapped),
          [ih] "r"(hash_count_ptr),
          [nonce] "r"(nonce_ptr),
          [flag] "r"(mining_flag),
          [nd] "r"(&g_v5_delays[0])
        : "a2", "a3", "a4", "a5", "a6", "a8", "memory"
    );

    return *mining_flag;
}


/* ------------------------------------------------------------------ */
/* v6: v3 with the memw barriers removed.                              */
/*                                                                     */
/* RE finding (RESEARCH.md): NMMiner's hot loop issues ZERO memw. On   */
/* the classic ESP32, same-core writes into the DPORT/SHA space are    */
/* issued in order through the DPORT write FIFO, so TEXT stores stay   */
/* ordered before the START/CONTINUE/LOAD trigger that follows them.   */
/* Each memw forces a full write-pipeline drain (~15-20 cyc); v3 has   */
/* five per nonce. Correctness is preserved by the bounded busy-polls  */
/* (engine completion is always confirmed) and by the software         */
/* verification of every candidate before submission.                  */
/* ------------------------------------------------------------------ */

#if defined(PIPE_V6)

bool IRAM_ATTR sha256_pipelined_mine_v6(
    volatile uint32_t *sha_base,
    const uint32_t *header_swapped,
    uint32_t *nonce_ptr,
    volatile uint64_t *hash_count_ptr,
    volatile bool *mining_flag)
{
    DPORT_REG_SET_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_SHA);
    DPORT_REG_CLR_BIT(DPORT_PERI_RST_EN_REG, DPORT_PERI_EN_SHA | DPORT_PERI_EN_SECUREBOOT);

    asm volatile(
        "l32i.n   a2,  %[nonce], 0 \n"
        "addi     a5,  %[sb], 0x90 \n"
        "movi.n   a8,  0           \n"

    "v6_start: \n"

        "l32i.n    a3,  %[IN],  0  \n"
        "s32i.n    a3,  %[sb],  0  \n"
        "l32i.n    a3,  %[IN],  4  \n"
        "s32i.n    a3,  %[sb],  4  \n"
        "l32i.n    a3,  %[IN],  8  \n"
        "s32i.n    a3,  %[sb],  8  \n"
        "l32i.n    a3,  %[IN], 12  \n"
        "s32i.n    a3,  %[sb], 12  \n"
        "l32i.n    a3,  %[IN], 16  \n"
        "s32i.n    a3,  %[sb], 16  \n"
        "l32i.n    a3,  %[IN], 20  \n"
        "s32i.n    a3,  %[sb], 20  \n"
        "l32i.n    a3,  %[IN], 24  \n"
        "s32i.n    a3,  %[sb], 24  \n"
        "l32i.n    a3,  %[IN], 28  \n"
        "s32i.n    a3,  %[sb], 28  \n"
        "l32i.n    a3,  %[IN], 32  \n"
        "s32i.n    a3,  %[sb], 32  \n"
        "l32i.n    a3,  %[IN], 36  \n"
        "s32i.n    a3,  %[sb], 36  \n"
        "l32i.n    a3,  %[IN], 40  \n"
        "s32i.n    a3,  %[sb], 40  \n"
        "l32i.n    a3,  %[IN], 44  \n"
        "s32i.n    a3,  %[sb], 44  \n"
        "l32i.n    a3,  %[IN], 48  \n"
        "s32i.n    a3,  %[sb], 48  \n"
        "l32i.n    a3,  %[IN], 52  \n"
        "s32i.n    a3,  %[sb], 52  \n"
        "l32i.n    a3,  %[IN], 56  \n"
        "s32i.n    a3,  %[sb], 56  \n"
        "l32i.n    a3,  %[IN], 60  \n"
        "s32i.n    a3,  %[sb], 60  \n"

        "movi.n  a3, 1             \n"
        "s32i.n  a3, a5, 0         \n"      /* SHA_START, no memw */

        "l32i    a3,  %[IN], 64    \n"
        "s32i.n  a3,  %[sb],  0    \n"
        "l32i    a3,  %[IN], 68    \n"
        "s32i.n  a3,  %[sb],  4    \n"
        "l32i    a3,  %[IN], 72    \n"
        "s32i.n  a3,  %[sb],  8    \n"
        "s32i.n  a2, %[sb], 12     \n"
        "movi    a3, 0x80000000    \n"
        "s32i.n  a3,  %[sb], 16    \n"
        "s32i.n  a8,  %[sb], 20    \n"
        "s32i.n  a8,  %[sb], 24    \n"
        "s32i.n  a8,  %[sb], 28    \n"
        "s32i.n  a8,  %[sb], 32    \n"
        "s32i.n  a8,  %[sb], 36    \n"
        "s32i.n  a8,  %[sb], 40    \n"
        "s32i.n  a8,  %[sb], 44    \n"
        "s32i.n  a8,  %[sb], 48    \n"
        "s32i.n  a8,  %[sb], 52    \n"
        "s32i.n  a8,  %[sb], 56    \n"
        "movi    a3, 0x280         \n"
        "s32i.n  a3,  %[sb], 60    \n"

    "v6_wait1: \n"
        "l32i.n  a3, a5, 12        \n"
        "bnez.n  a3, v6_wait1      \n"

        "movi.n  a3, 1             \n"
        "s32i.n  a3, a5, 4         \n"      /* SHA_CONTINUE, no memw */

    "v6_wait2: \n"
        "l32i.n  a4, a5, 12        \n"
        "bnez.n  a4, v6_wait2      \n"

        "movi.n  a4, 1             \n"
        "s32i.n  a4, a5, 8         \n"      /* SHA_LOAD, no memw */

        "addi.n  a2, a2, 1         \n"

    "v6_wait3: \n"
        "l32i.n  a4, a5, 12        \n"
        "bnez.n  a4, v6_wait3      \n"

        "movi    a3, 0x80000000    \n"
        "s32i.n  a3,  %[sb], 32    \n"
        "movi    a3, 0x100         \n"
        "s32i.n  a3,  %[sb], 60    \n"

        "movi.n  a4, 1             \n"
        "s32i.n  a4, a5, 0         \n"      /* SHA_START double, no memw */

        "l32i.n  a3, %[ih], 0      \n"
        "addi.n  a3, a3, 1         \n"
        "s32i.n  a3, %[ih], 0      \n"
        "bnez.n  a3, v6_no_carry   \n"
        "l32i.n  a4, %[ih], 4      \n"
        "addi.n  a4, a4, 1         \n"
        "s32i.n  a4, %[ih], 4      \n"
    "v6_no_carry: \n"

    "v6_wait4: \n"
        "l32i.n  a4, a5, 12        \n"
        "bnez.n  a4, v6_wait4      \n"

        "movi.n  a3, 1             \n"
        "s32i.n  a3, a5, 8         \n"      /* SHA_LOAD, no memw */

    "v6_wait5: \n"
        "l32i.n  a4, a5, 12        \n"
        "bnez.n  a4, v6_wait5      \n"

        "l8ui   a3, %[flag], 0     \n"
        "beqz.n a3, v6_end         \n"

        "l16ui  a3, %[sb], 28      \n"
        "beqz.n a3, v6_end         \n"

        "j v6_start                \n"

    "v6_end: \n"
        "s32i.n a2, %[nonce], 0    \n"

        :
        : [sb] "r"(sha_base),
          [IN] "r"(header_swapped),
          [ih] "r"(hash_count_ptr),
          [nonce] "r"(nonce_ptr),
          [flag] "r"(mining_flag)
        : "a2", "a3", "a4", "a5", "a8", "memory"
    );

    return *mining_flag;
}

#endif // PIPE_V6


/* ------------------------------------------------------------------ */
/* v9: NMMiner-shaped pipeline (see RESEARCH.md section 3).             */
/*                                                                     */
/* DO NOT "optimize" the per-nonce 64-bit counter update or the tail    */
/* restore into register-cached stores without re-running the A/B/A     */
/* benchmark (bench/BENCH.md round 3): a 2026-08-18 rewrite doing      */
/* exactly that measured 0.8% SLOWER (core1 775.0 vs 781.3/781.8) -    */
/* removed instructions overlapped free engine-wait time, while the    */
/* changed DPORT store pattern in the tail hurt. Old schedule kept.    */
/*                                                                     */
/* Same five engine ops per nonce as v3, but restructured so the        */
/* midstate (block-1) START issued at the tail of iteration N hides    */
/* completely under iteration N+1's stores, block-1 restoration is     */
/* split around the pipeline, and all waits are tunable-delay +        */
/* bounded-poll (correctness never depends on timing).                 */
/*                                                                     */
/* Per nonce:  CONT(blk2) LOAD START(hash2) LOAD  [check]  blk1-words  */
/*             START(midstate for next nonce)                           */
/* TEXT timeline (words):                                              */
/*   ... [blk1 w0-7][blk1 w8-15]  <- midstate START snapshot           */
/*   [blk2 0-15]                  <- CONT snapshot                     */
/*   [blk2 0-7][pad][zeros][len2] -> LOAD#1 writes D1 over 0-7         */
/*   [D1][pad][zeros][len2]       <- START(hash2) snapshot             */
/*   [D2 (via LOAD#2)][blk1 w8-15 restored during hash2]               */
/*   [blk1 w0-7 restored][blk1 w8-15] <- next midstate START           */
/* ------------------------------------------------------------------ */

#if defined(PIPE_V9)

#ifndef V9_DELAY_DEFAULTS
#define V9_DELAY_DEFAULTS {0, 8, 0, 8, 0}   /* empirical optimum (autoresearch sweep 2026-08-17) */
#endif

bool IRAM_ATTR sha256_pipelined_mine_v9(
    volatile uint32_t *sha_base,
    const uint32_t *header_swapped,
    uint32_t *nonce_ptr,
    volatile uint64_t *hash_count_ptr,
    volatile bool *mining_flag)
{
    DPORT_REG_SET_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_SHA);
    DPORT_REG_CLR_BIT(DPORT_PERI_RST_EN_REG, DPORT_PERI_EN_SHA | DPORT_PERI_EN_SECUREBOOT);

    static const uint16_t d0[5] = V9_DELAY_DEFAULTS;
    static bool s_v9_seeded = false;
    if (!s_v9_seeded) {
        for (int i = 0; i < 5; i++) g_v5_delays[i] = d0[i];
        s_v9_seeded = true;
        Serial.printf("[V9] delays seeded n=[%u,%u,%u,%u,%u]\n",
                      d0[0], d0[1], d0[2], d0[3], d0[4]);
    }

    /* per-job staging buffers (swapped words):
     * blk1[16] = header words 0..15
     * blk2[16] = [merkle_w7, time, nbits, nonce][0x80000000][0 x10][0x280]  */
    static uint32_t blk1[16], blk2[16];
    for (int i = 0; i < 16; i++) blk1[i] = header_swapped[i];
    for (int i = 0; i < 4; i++)  blk2[i] = header_swapped[16 + i];
    blk2[4] = 0x80000000u;
    for (int i = 5; i < 15; i++) blk2[i] = 0;
    blk2[15] = 0x280u;
    blk2[3] = *nonce_ptr;          /* continue the nonce sweep (swapped repr) */

    asm volatile(
        "mov.n   a2,  %[sb]          \n"   /* a2 = TEXT base                  */
        "addi    a5,  %[sb], 0x90    \n"   /* a5 = control base               */

        /* ---- init: full block 1 into TEXT, start midstate hash ---- */
        "l32i.n  a10, %[b1], 0       \n"
        "s32i.n  a10, a2,  0         \n"
        "l32i.n  a10, %[b1], 4       \n"
        "s32i.n  a10, a2,  4         \n"
        "l32i.n  a10, %[b1], 8       \n"
        "s32i.n  a10, a2,  8         \n"
        "l32i.n  a10, %[b1], 12      \n"
        "s32i.n  a10, a2,  12        \n"
        "l32i.n  a10, %[b1], 16      \n"
        "s32i.n  a10, a2,  16        \n"
        "l32i.n  a10, %[b1], 20      \n"
        "s32i.n  a10, a2,  20        \n"
        "l32i.n  a10, %[b1], 24      \n"
        "s32i.n  a10, a2,  24        \n"
        "l32i.n  a10, %[b1], 28      \n"
        "s32i.n  a10, a2,  28        \n"
        "l32i.n  a10, %[b1], 32      \n"
        "s32i.n  a10, a2,  32        \n"
        "l32i.n  a10, %[b1], 36      \n"
        "s32i.n  a10, a2,  36        \n"
        "l32i.n  a10, %[b1], 40      \n"
        "s32i.n  a10, a2,  40        \n"
        "l32i.n  a10, %[b1], 44      \n"
        "s32i.n  a10, a2,  44        \n"
        "l32i.n  a10, %[b1], 48      \n"
        "s32i.n  a10, a2,  48        \n"
        "l32i.n  a10, %[b1], 52      \n"
        "s32i.n  a10, a2,  52        \n"
        "l32i.n  a10, %[b1], 56      \n"
        "s32i.n  a10, a2,  56        \n"
        "l32i.n  a10, %[b1], 60      \n"
        "s32i.n  a10, a2,  60        \n"
        "movi.n  a10, 1              \n"
        "s32i.n  a10, a5,  0         \n"   /* START: midstate (hidden under next iter) */

    "v9_top: \n"
        /* hash counter += 1 (64-bit) */
        "l32i.n  a10, %[ih], 0       \n"
        "addi.n  a10, a10, 1         \n"
        "s32i.n  a10, %[ih], 0       \n"
        "bnez.n  a10, v9_nc          \n"
        "l32i.n  a11, %[ih], 4       \n"
        "addi.n  a11, a11, 1         \n"
        "s32i.n  a11, %[ih], 4       \n"
    "v9_nc: \n"
        /* nonce (blk2 word 3, swapped repr) += 1 */
        "l32i.n  a10, %[b2], 12      \n"
        "addi.n  a10, a10, 1         \n"
        "s32i.n  a10, %[b2], 12      \n"

        /* copy blk2 (16 words) into TEXT while midstate runs */
        "l32i.n  a10, %[b2], 0       \n"
        "s32i.n  a10, a2,  0         \n"
        "l32i.n  a10, %[b2], 4       \n"
        "s32i.n  a10, a2,  4         \n"
        "l32i.n  a10, %[b2], 8       \n"
        "s32i.n  a10, a2,  8         \n"
        "l32i.n  a10, %[b2], 12      \n"
        "s32i.n  a10, a2,  12        \n"
        "l32i.n  a10, %[b2], 16      \n"
        "s32i.n  a10, a2,  16        \n"
        "l32i.n  a10, %[b2], 20      \n"
        "s32i.n  a10, a2,  20        \n"
        "l32i.n  a10, %[b2], 24      \n"
        "s32i.n  a10, a2,  24        \n"
        "l32i.n  a10, %[b2], 28      \n"
        "s32i.n  a10, a2,  28        \n"
        "l32i.n  a10, %[b2], 32      \n"
        "s32i.n  a10, a2,  32        \n"
        "l32i.n  a10, %[b2], 36      \n"
        "s32i.n  a10, a2,  36        \n"
        "l32i.n  a10, %[b2], 40      \n"
        "s32i.n  a10, a2,  40        \n"
        "l32i.n  a10, %[b2], 44      \n"
        "s32i.n  a10, a2,  44        \n"
        "l32i.n  a10, %[b2], 48      \n"
        "s32i.n  a10, a2,  48        \n"
        "l32i.n  a10, %[b2], 52      \n"
        "s32i.n  a10, a2,  52        \n"
        "l32i.n  a10, %[b2], 56      \n"
        "s32i.n  a10, a2,  56        \n"
        "l32i.n  a10, %[b2], 60      \n"
        "s32i.n  a10, a2,  60        \n"

        /* w1: midstate wait (mostly hidden) */
        "l16ui   a10, %[nd], 0       \n"
        "beqz.n  a10, v9_p1          \n"
    "v9_d1: \n"
        "addi    a10, a10, -1        \n"
        "bnez.n  a10, v9_d1          \n"
    "v9_p1: \n"
        "l32i.n  a10, a5, 12         \n"
        "bnez.n  a10, v9_p1          \n"

        "movi.n  a10, 1              \n"
        "s32i.n  a10, a5,  4         \n"   /* CONTINUE: blk2 (hash1 complete) */

        /* w2: blk2 hash */
        "l16ui   a10, %[nd], 2       \n"
        "beqz.n  a10, v9_p2          \n"
    "v9_d2: \n"
        "addi    a10, a10, -1        \n"
        "bnez.n  a10, v9_d2          \n"
    "v9_p2: \n"
        "l32i.n  a10, a5, 12         \n"
        "bnez.n  a10, v9_p2          \n"

        /* build hash2 block tail (over blk2's consumed words) */
        "movi    a10, 0x80000000     \n"
        "s32i.n  a10, a2,  32        \n"   /* pad at word 8  */
        "movi    a10, 0x100          \n"
        "s32i.n  a10, a2,  60        \n"   /* 256-bit length at word 15 */

        "movi.n  a10, 1              \n"
        "s32i.n  a10, a5,  8         \n"   /* LOAD#1: D1 -> TEXT[0..7] */

        /* w3: LOAD wait */
        "l16ui   a10, %[nd], 4       \n"
        "beqz.n  a10, v9_p3          \n"
    "v9_d3: \n"
        "addi    a10, a10, -1        \n"
        "bnez.n  a10, v9_d3          \n"
    "v9_p3: \n"
        "l32i.n  a10, a5, 12         \n"
        "bnez.n  a10, v9_p3          \n"

        "movi.n  a10, 1              \n"
        "s32i.n  a10, a5,  0         \n"   /* START: hash2 on [D1|pad|len] */

        /* overlap: restore blk1 words 8-15 while hash2 runs */
        "l32i.n  a10, %[b1], 32      \n"
        "s32i.n  a10, a2,  32        \n"
        "l32i.n  a10, %[b1], 36      \n"
        "s32i.n  a10, a2,  36        \n"
        "l32i.n  a10, %[b1], 40      \n"
        "s32i.n  a10, a2,  40        \n"
        "l32i.n  a10, %[b1], 44      \n"
        "s32i.n  a10, a2,  44        \n"
        "l32i.n  a10, %[b1], 48      \n"
        "s32i.n  a10, a2,  48        \n"
        "l32i.n  a10, %[b1], 52      \n"
        "s32i.n  a10, a2,  52        \n"
        "l32i.n  a10, %[b1], 56      \n"
        "s32i.n  a10, a2,  56        \n"
        "l32i.n  a10, %[b1], 60      \n"
        "s32i.n  a10, a2,  60        \n"

        /* w4: hash2 */
        "l16ui   a10, %[nd], 6       \n"
        "beqz.n  a10, v9_p4          \n"
    "v9_d4: \n"
        "addi    a10, a10, -1        \n"
        "bnez.n  a10, v9_d4          \n"
    "v9_p4: \n"
        "l32i.n  a10, a5, 12         \n"
        "bnez.n  a10, v9_p4          \n"

        "movi.n  a10, 1              \n"
        "s32i.n  a10, a5,  8         \n"   /* LOAD#2: D2 -> TEXT[0..7] */

        /* w5: LOAD wait */
        "l16ui   a10, %[nd], 8       \n"
        "beqz.n  a10, v9_p5          \n"
    "v9_d5: \n"
        "addi    a10, a10, -1        \n"
        "bnez.n  a10, v9_d5          \n"
    "v9_p5: \n"
        "l32i.n  a10, a5, 12         \n"
        "bnez.n  a10, v9_p5          \n"

        "l8ui    a10, %[flag], 0     \n"
        "beqz.n  a10, v9_end         \n"

        "l16ui   a10, a2,  28        \n"   /* early reject on D2 */
        "beqz.n  a10, v9_end         \n"   /* candidate! */

        /* tail: restore blk1 words 0-7 (clobbered by LOAD#2) and
         * START the midstate for the next nonce (hidden under w1) */
        "l32i.n  a10, %[b1], 0       \n"
        "s32i.n  a10, a2,  0         \n"
        "l32i.n  a10, %[b1], 4       \n"
        "s32i.n  a10, a2,  4         \n"
        "l32i.n  a10, %[b1], 8       \n"
        "s32i.n  a10, a2,  8         \n"
        "l32i.n  a10, %[b1], 12      \n"
        "s32i.n  a10, a2,  12        \n"
        "l32i.n  a10, %[b1], 16      \n"
        "s32i.n  a10, a2,  16        \n"
        "l32i.n  a10, %[b1], 20      \n"
        "s32i.n  a10, a2,  20        \n"
        "l32i.n  a10, %[b1], 24      \n"
        "s32i.n  a10, a2,  24        \n"
        "l32i.n  a10, %[b1], 28      \n"
        "s32i.n  a10, a2,  28        \n"
        "movi.n  a10, 1              \n"
        "s32i.n  a10, a5,  0         \n"   /* START: midstate */

        "j       v9_top              \n"

    "v9_end: \n"
        /* NOTE: the candidate nonce already lives in blk2[3] (DRAM); the C
         * epilogue (*nonce_ptr = blk2[3]) propagates it. Do NOT store a10
         * here - both exits arrive with a10==0 (flag byte or l16ui test),
         * which would erase the real candidate nonce. */

        :
        : [sb]  "r"(sha_base),
          [b1]  "r"(blk1),
          [b2]  "r"(blk2),
          [ih]  "r"(hash_count_ptr),
          [flag] "r"(mining_flag),
          [nd]  "r"(&g_v5_delays[0])
        : "a2", "a5", "a10", "a11", "memory"
    );

    /* Candidate nonce = the value just hashed (incremented before use,
     * unlike v3 which pre-increments => caller must NOT subtract 1). */
    *nonce_ptr = blk2[3];
    return *mining_flag;
}

#endif // PIPE_V9

/* ------------------------------------------------------------------ */
/* Serial tuner                                                        */
/* ------------------------------------------------------------------ */

void v5_handle_serial(void)
{
    static char buf[64];
    static uint8_t bi = 0;

    while (Serial.available() > 0) {
        char c = (char)Serial.read();
        if (c == '\n' || c == '\r') {
            if (bi > 0) {
                buf[bi] = 0;
                bi = 0;
                if (!strncmp(buf, "TUNE?", 5)) {
                    Serial.printf("[V5] TUNE n=[%u,%u,%u,%u,%u] autocal=%u\n",
                                  g_v5_delays[0], g_v5_delays[1], g_v5_delays[2],
                                  g_v5_delays[3], g_v5_delays[4], g_v5_autocal);
                } else if (!strncmp(buf, "TUNE ", 5)) {
                    unsigned v[5] = {0, 0, 0, 0, 0};
                    int n = sscanf(buf + 5, "%u,%u,%u,%u,%u", &v[0], &v[1], &v[2], &v[3], &v[4]);
                    if (n >= 1) {
                        for (int i = 0; i < 5; i++)
                            if (v[i] > 4000) v[i] = 4000;
                        g_v5_delays[0] = v[0]; g_v5_delays[1] = v[1]; g_v5_delays[2] = v[2];
                        g_v5_delays[3] = v[3]; g_v5_delays[4] = v[4];
                        Serial.printf("[V5] TUNE-OK n=[%u,%u,%u,%u,%u]\n",
                                      v[0], v[1], v[2], v[3], v[4]);
                    } else {
                        Serial.println("[V5] TUNE parse error (use: TUNE n1,n2,n3,n4,n5)");
                    }
                } else if (!strncmp(buf, "CAL", 3)) {
                    v5_force_recal();
                    Serial.println("[V5] recal requested (applies at next job)");
                } else if (!strncmp(buf, "AUTOCAL ", 8)) {
                    int en = 0;
                    sscanf(buf + 8, "%d", &en);
                    g_v5_autocal = (en != 0);
                    Serial.printf("[V5] autocal=%u\n", g_v5_autocal ? 1 : 0);
                }
            }
        } else if (bi < sizeof(buf) - 1) {
            buf[bi++] = c;
        } else {
            bi = 0;
        }
    }
}

#endif // CONFIG_IDF_TARGET_ESP32 && PIPE_V5
