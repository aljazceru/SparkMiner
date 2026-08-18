/*
 * SparkMiner - Pipelined SHA-256 v5: NOP-timed busy-waits with auto-calibration
 *
 * Derived from sha256_pipelined_v3 (BitsyMiner lineage, GPL v3).
 *
 * Idea ported from NMMiner firmware analysis (see ../../RESEARCH.md):
 * instead of busy-polling SHA_256_BUSY_REG after each engine operation,
 * spin a calibrated number of delay-loop iterations first, then fall into
 * a bounded busy-poll. Correctness NEVER depends on the timing:
 *  - delay too short -> the poll catches the tail (correct, tiny cost)
 *  - delay too long  -> wasted cycles (correct, slower)
 *
 * The five delay iteration counts live in g_v5_delays[] (volatile). On the
 * first call the engine phase residuals are measured with CCOUNT and the
 * delays are auto-calibrated per device / chip revision. They can also be
 * overridden at runtime over serial:
 *    TUNE n1,n2,n3,n4,n5   - set delays (iterations, 16-bit each)
 *    TUNE?                 - print current delays
 *    CAL                   - re-run auto-calibration on next job
 *    AUTOCAL 0|1           - enable/disable auto calibration
 */

#ifndef SHA256_PIPELINED_V5_H_
#define SHA256_PIPELINED_V5_H_

#include <stdint.h>
#include <stdbool.h>
#include <esp_attr.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_IDF_TARGET_ESP32)

/* Delay iteration counts for the five wait sites (0 = pure busy-poll, v3 behaviour).
 * w1: block1 (64B) after SHA_START
 * w2: block2 (16B+pad) after SHA_CONTINUE
 * w3: SHA_LOAD of intermediate digest
 * w4: double-hash block after SHA_START
 * w5: SHA_LOAD of final digest
 */
extern volatile uint16_t g_v5_delays[5];
extern volatile bool g_v5_autocal;

bool IRAM_ATTR sha256_pipelined_mine_v5(
    volatile uint32_t *sha_base,
    const uint32_t *header_swapped,
    uint32_t *nonce_ptr,
    volatile uint64_t *hash_count_ptr,
    volatile bool *mining_flag
);

/* Force re-run of auto-calibration on the next mine call. */
void v5_force_recal(void);

#if defined(PIPE_V9)
/* v9: NMMiner-shaped pipeline (tail-issued midstate START, split block-1
 * restore, tunable waits). Candidate nonce = *nonce_ptr as returned. */
bool IRAM_ATTR sha256_pipelined_mine_v9(
    volatile uint32_t *sha_base,
    const uint32_t *header_swapped,
    uint32_t *nonce_ptr,
    volatile uint64_t *hash_count_ptr,
    volatile bool *mining_flag
);
#endif

#if defined(PIPE_V6)
/* v6: v3 with memw barriers removed (NMMiner-style, see RESEARCH.md). */
bool IRAM_ATTR sha256_pipelined_mine_v6(
    volatile uint32_t *sha_base,
    const uint32_t *header_swapped,
    uint32_t *nonce_ptr,
    volatile uint64_t *hash_count_ptr,
    volatile bool *mining_flag
);
#endif

#endif // CONFIG_IDF_TARGET_ESP32

#ifdef __cplusplus
} /* extern "C" */
#endif

/* Non-blocking serial tuner (call periodically from a low-priority task). C++ side. */
void v5_handle_serial(void);

#endif /* SHA256_PIPELINED_V5_H_ */
