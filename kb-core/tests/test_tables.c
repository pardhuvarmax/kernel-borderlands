// SPDX-License-Identifier: GPL-2.0
// Regression tests for the per-pid tables (scoring, evidence, behavior).
//
// These tables used to probe linearly over the whole table with hash = pid % N.
// Under a process storm (sequential pids) or after lost exit events left stale
// entries, every lookup scanned thousands of slots (40-55% of the sensor's CPU),
// and a full behavior table made kb_behavior_evaluate() return no record, which
// the caller dereferenced (SIGSEGV exactly when overloaded).
//
// Build/run from kb-core/ (no root, no kernel needed), one command:
//   gcc -O2 -Wall -I include -o /tmp/test_tables tests/test_tables.c userspace/behavior/kb_scoring.c userspace/behavior/kb_evidence.c userspace/behavior/kb_behavior.c userspace/behavior/kb_rules.c -lm && /tmp/test_tables

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/kb_scoring.h"
#include "../include/kb_evidence.h"
#include "../include/kb_behavior.h"

#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s (line %d)\n", msg, __LINE__); exit(1); } } while (0)

static int alive_mod3(uint32_t pid) { return pid % 3 != 0; }   // pids divisible by 3 are "dead"

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void test_never_null_and_bounded_under_storm(void)
{
    kb_scoring_init(); kb_evidence_init(); kb_behavior_init();
    // Far more distinct pids than any table holds, all sequential, none ever
    // exited: the old tables filled up and then returned NULL / scanned O(N).
    double t0 = now_s();
    for (uint32_t pid = 1000; pid < 1000 + 200000; pid++) {
        kb_evidence_t *ev = kb_evidence_get_or_create(pid, 1, 1000, "storm", pid);
        CHECK(ev != NULL, "evidence get_or_create must never return NULL");
        struct kb_unified_event e = {0};
        e.pid = pid; e.event_type = 0;
        kb_scoring_result_t r = kb_scoring_update(&e);
        CHECK(r.state != NULL, "scoring update must never lose the state");
        kb_behavior_result_t b = kb_behavior_evaluate(ev);
        CHECK(b.record != NULL, "behavior evaluate must always return a record");
    }
    double took = now_s() - t0;
    printf("(200k sequential pids in %.3fs) ", took);
    CHECK(took < 3.0, "200k inserts took too long: lookups are not bounded");
    CHECK(kb_scoring_evictions() > 0 && kb_evidence_evictions() > 0 && kb_behavior_evictions() > 0,
          "overflow must be handled by counted evictions");
}

static void test_eviction_keeps_the_evidenced_process(void)
{
    kb_evidence_init();
    // One process with strong evidence among a flood of quiet ones that all
    // hash into overlapping windows: it must survive.
    kb_evidence_t *hot = kb_evidence_get_or_create(777777, 1, 0, "evil", 1);
    CHECK(hot != NULL, "create");
    kb_evidence_set_flag(hot, KB_EV_SHADOW_ACCESS, 1);
    kb_evidence_set_flag(hot, KB_EV_RWX_MAPPING, 2);
    kb_evidence_set_flag(hot, KB_EV_OUTBOUND_CONNECT, 3);
    for (uint32_t pid = 1; pid < 300000; pid++)
        kb_evidence_get_or_create(pid, 1, 1000, "quiet", pid);
    kb_evidence_t *again = kb_evidence_get(777777);
    CHECK(again != NULL && again->flags != 0, "a process with evidence must not be evicted in favour of quiet ones");
}

static void test_reap_drops_only_dead_and_keeps_lookups_working(void)
{
    kb_scoring_init(); kb_evidence_init(); kb_behavior_init();
    for (uint32_t pid = 100; pid < 2100; pid++) {
        kb_evidence_get_or_create(pid, 1, 1000, "p", pid);
        struct kb_unified_event e = {0};
        e.pid = pid; e.event_type = 0;
        kb_scoring_update(&e);
        kb_behavior_evaluate(kb_evidence_get(pid));
    }
    int e0 = kb_evidence_occupancy(), s0 = kb_scoring_occupancy(), b0 = kb_behavior_occupancy();
    int de = kb_evidence_reap(alive_mod3), ds = kb_scoring_reap(alive_mod3), db = kb_behavior_reap(alive_mod3);
    CHECK(de > 0 && ds > 0 && db > 0, "reap must drop the dead entries");
    CHECK(kb_evidence_occupancy() == e0 - de && kb_scoring_occupancy() == s0 - ds &&
          kb_behavior_occupancy() == b0 - db, "occupancy must match what was dropped");
    for (uint32_t pid = 100; pid < 2100; pid++) {
        if (pid % 3 == 0) {
            CHECK(kb_evidence_get(pid) == NULL, "dead pid must be gone");
        } else {
            CHECK(kb_evidence_get(pid) != NULL && kb_scoring_get_state(pid) != NULL && kb_behavior_get(pid) != NULL,
                  "live pid must still be found after a rebuild");
        }
    }
}

static void test_freed_slot_does_not_hide_later_entries(void)
{
    // The old tables stopped at the first empty slot, so removing one entry
    // (exit event) made colliding entries behind it unreachable.
    kb_scoring_init();
    for (uint32_t pid = 5000; pid < 5400; pid++) {
        struct kb_unified_event e = {0};
        e.pid = pid;
        kb_scoring_update(&e);
    }
    for (uint32_t pid = 5000; pid < 5400; pid += 2)
        kb_scoring_remove(pid);
    for (uint32_t pid = 5001; pid < 5400; pid += 2)
        CHECK(kb_scoring_get_state(pid) != NULL, "removing a neighbour must not hide a live entry");
}

#define RUN(t) do { printf("Running " #t "... "); t(); printf("PASS\n"); } while (0)
int main(void)
{
    RUN(test_never_null_and_bounded_under_storm);
    RUN(test_eviction_keeps_the_evidenced_process);
    RUN(test_reap_drops_only_dead_and_keeps_lookups_working);
    RUN(test_freed_slot_does_not_hide_later_entries);
    printf("All table tests passed\n");
    return 0;
}
