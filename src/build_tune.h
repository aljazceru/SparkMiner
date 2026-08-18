#pragma once
/*
 * SparkMiner - build-time experiment overrides for the hashrate autoresearch
 * loop (see ../bench/autoresearch.py and ../bench/BENCH.md).
 *
 * All switches undefined = stock behaviour. The autoresearch script rewrites
 * this file per experiment and restores this exact template afterwards.
 *
 *   PIPE_V5 1            - NOP-timed busy-waits + CCOUNT auto-calibration
 *   PIPE_V6 1            - v3 with memw barriers removed (experimental)
 *   PIPE_V9 1            - NMMiner-shaped pipeline (winner, see BENCH.md)
 *   USE_NERD_SW 1        - NerdMiner nerdSHA256plus SW miner on core 0
 *                          (net negative on classic ESP32 - see BENCH.md r2)
 *   SW_CROSSCHECK 1      - boot-time double-hash equivalence check (nerd port)
 *   QUIET_MINER 1        - silence core-1 hot-path UART prints
 *   FORCE_STATS_OFF 1    - do not start the live-stats HTTP task
 *   DISPLAY_UPDATE_MS N  - TFT refresh period (default 1000)
 *   BUTTON_POLL_MS N     - button task poll period (default 10)
 *   CORE_0_YIELD_COUNT N - SW miner yields every N hashes (default 512)
 */
