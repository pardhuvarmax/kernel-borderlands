// SPDX-License-Identifier: GPL-2.0
// KB Core — Behavior Engine Unit Tests

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "../include/kb_scoring.h"
#include "../include/kb_evidence.h"
#include "../include/kb_behavior.h"
#include "../include/kb_rules.h"
#include "../include/kb_memclass.h"

// Define a test runner macro
#define RUN_TEST(test) \
    do { \
        printf("Running " #test "... "); \
        test(); \
        printf("PASS\n"); \
    } while (0)

// Helper to simulate a simple unified event
static struct kb_unified_event make_event(uint32_t pid, uint8_t event_type, uint64_t ts_ns)
{
    struct kb_unified_event e;
    memset(&e, 0, sizeof(e));
    e.pid = pid;
    e.ppid = 1;
    e.uid = 1000;
    strcpy((char *)e.comm, "test_proc");
    e.event_type = event_type;
    e.ts_ns = ts_ns;
    return e;
}

// Test 1: Verify initialization and simple SAFE state
static void test_initialization(void)
{
    kb_evidence_init();
    kb_behavior_init();

    kb_evidence_t *ev = kb_evidence_get(1234);
    assert(ev == NULL);

    kb_behavior_record_t *rec = kb_behavior_get(1234);
    assert(rec == NULL);
}

// Test 2: Verify sequential transition SAFE -> OBSERVED -> SUSPICIOUS -> BORDERLANDS -> COMPROMISED
static void test_sequential_transitions(void)
{
    kb_evidence_init();
    kb_behavior_init();
    kb_scoring_init();

    uint32_t pid = 2222;
    uint64_t ts = 1000000000ULL; // 1s

    // Fetch process state records
    kb_evidence_t *ev = kb_evidence_get_or_create(pid, 1, 1000, "test_proc", ts);
    assert(ev != NULL);

    // Initial state check
    kb_behavior_result_t r = kb_behavior_evaluate(ev);
    assert(r.record->state == KB_STATE_SAFE);
    assert(r.state_changed == 0);

    // 1. Trigger SAFE -> OBSERVED via privilege change
    kb_evidence_set_flag(ev, KB_EV_PRIVILEGE_GAINED, ts);
    r = kb_behavior_evaluate(ev);
    assert(r.state_changed == 1);
    assert(r.prev_state == KB_STATE_SAFE);
    assert(r.new_state == KB_STATE_OBSERVED);
    assert(r.reason == KB_REASON_PRIVILEGE_CHANGE);

    // 2. Trigger OBSERVED -> SUSPICIOUS via credential file access
    ts += 1000000000ULL; // +1s
    kb_evidence_set_flag(ev, KB_EV_SHADOW_ACCESS, ts);
    kb_evidence_push_seq(ev, KB_SEQ_CRED_FILE);
    r = kb_behavior_evaluate(ev);
    assert(r.state_changed == 1);
    assert(r.prev_state == KB_STATE_OBSERVED);
    assert(r.new_state == KB_STATE_SUSPICIOUS);
    assert(r.reason == KB_REASON_CRED_FILE_ACCESS);

    // 3. Trigger SUSPICIOUS -> BORDERLANDS via RWX memory mapping
    ts += 1000000000ULL; // +1s
    kb_evidence_set_flag(ev, KB_EV_RWX_MAPPING, ts);
    kb_evidence_push_seq(ev, KB_SEQ_RWX_MAP);
    r = kb_behavior_evaluate(ev);
    assert(r.state_changed == 1);
    assert(r.prev_state == KB_STATE_SUSPICIOUS);
    assert(r.new_state == KB_STATE_BORDERLANDS);
    assert(r.reason == KB_REASON_RWX_MEMORY);

    // 4. Trigger BORDERLANDS -> COMPROMISED via reverse shell (outbound + shell spawned sequence)
    ts += 1000000000ULL; // +1s
    kb_evidence_set_flag(ev, KB_EV_OUTBOUND_CONNECT, ts);
    kb_evidence_push_seq(ev, KB_SEQ_OUTBOUND_CONNECT);
    kb_evidence_set_flag(ev, KB_EV_SPAWNED_SHELL, ts + 10000000ULL);
    kb_evidence_push_seq(ev, KB_SEQ_EXEC_SHELL);
    
    r = kb_behavior_evaluate(ev);
    assert(r.state_changed == 1);
    assert(r.prev_state == KB_STATE_BORDERLANDS);
    assert(r.new_state == KB_STATE_COMPROMISED);
    assert(r.reason == KB_REASON_REVERSE_SHELL_CHAIN);
}

// Test 3: Verify high-confidence direct transition SAFE -> COMPROMISED via IOC sequence
static void test_direct_ioc_compromised(void)
{
    kb_evidence_init();
    kb_behavior_init();
    kb_scoring_init();

    uint32_t pid = 3333;
    uint64_t ts = 1000000000ULL;

    kb_evidence_t *ev = kb_evidence_get_or_create(pid, 1, 1000, "test_proc", ts);
    
    // Simulate exact IOC sequence: exec -> outbound -> RWX mapping within 30 seconds
    kb_evidence_push_seq(ev, KB_SEQ_EXEC);
    ev->first_exec_ns = ts;

    ts += 5000000000ULL; // +5s
    kb_evidence_set_flag(ev, KB_EV_EXEC_FROM_TMP, ts); // sets optional flag

    ts += 5000000000ULL; // +5s
    kb_evidence_set_flag(ev, KB_EV_OUTBOUND_CONNECT, ts);
    kb_evidence_push_seq(ev, KB_SEQ_OUTBOUND_CONNECT);

    ts += 5000000000ULL; // +5s
    kb_evidence_set_flag(ev, KB_EV_RWX_MAPPING, ts);
    kb_evidence_push_seq(ev, KB_SEQ_RWX_MAP);

    // Evaluate
    kb_behavior_result_t r = kb_behavior_evaluate(ev);
    assert(r.state_changed == 1);
    assert(r.prev_state == KB_STATE_SAFE);
    assert(r.new_state == KB_STATE_COMPROMISED);
    assert(r.reason == KB_REASON_KNOWN_IOC_SEQUENCE);
}

// Test 4: Verify time window checks (if events are too far apart, the rule should not trigger)
static void test_time_window_validation(void)
{
    kb_evidence_init();
    kb_behavior_init();
    kb_scoring_init();

    uint32_t pid = 4444;
    uint64_t ts = 1000000000ULL;

    kb_evidence_t *ev = kb_evidence_get_or_create(pid, 1, 1000, "test_proc", ts);

    // Sequence matches, but time window exceeded:
    // First event (exec)
    kb_evidence_push_seq(ev, KB_SEQ_EXEC);
    ev->first_exec_ns = ts;

    ts += 5000000000ULL; // +5s
    kb_evidence_set_flag(ev, KB_EV_EXEC_FROM_TMP, ts);

    ts += 5000000000ULL; // +5s
    kb_evidence_set_flag(ev, KB_EV_OUTBOUND_CONNECT, ts);
    kb_evidence_push_seq(ev, KB_SEQ_OUTBOUND_CONNECT);

    // Gap is 40 seconds (greater than 30s rule limit)
    ts += 40000000000ULL; // +40s
    kb_evidence_set_flag(ev, KB_EV_RWX_MAPPING, ts);
    kb_evidence_push_seq(ev, KB_SEQ_RWX_MAP);

    // Evaluate: rule "known_ioc_sequence" should NOT trigger because of time window constraint
    kb_behavior_result_t r = kb_behavior_evaluate(ev);
    assert(r.new_state != KB_STATE_COMPROMISED);
}

// Test 5: spec state diagram, "OBSERVED --> BORDERLANDS : Memory Injection (process_vm_writev)"
// and the shellcode_injection sample rule (min_source_state SAFE): a cross-process
// memory write promotes straight to BORDERLANDS from a CLEAN process. It used to
// need SUSPICIOUS first, so a clean process could inject without any zone change.
static void test_cross_process_write_from_clean_process_is_borderlands(void)
{
    kb_evidence_init();
    kb_behavior_init();
    kb_scoring_init();

    uint64_t ts = 1000000000ULL;
    kb_evidence_t *ev = kb_evidence_get_or_create(5001, 1, 1000, "injector", ts);
    kb_evidence_set_flag(ev, KB_EV_PROC_MEM_WRITE, ts);        // what the sensor sets for process_vm_writev
    kb_evidence_push_seq(ev, KB_SEQ_PROC_MEM_WRITE);

    kb_behavior_result_t r = kb_behavior_evaluate(ev);
    assert(r.state_changed == 1);
    assert(r.prev_state == KB_STATE_SAFE);
    assert(r.new_state == KB_STATE_BORDERLANDS);
    assert(r.reason == KB_REASON_PROC_MEM_WRITE);
}

// Test 6: a plain RWX mapping (JITs, browsers) must NOT jump straight to BORDERLANDS
// from a clean process; it still needs SUSPICIOUS first.
static void test_rwx_mapping_alone_from_clean_process_is_not_borderlands(void)
{
    kb_evidence_init();
    kb_behavior_init();
    kb_scoring_init();

    uint64_t ts = 1000000000ULL;
    kb_evidence_t *ev = kb_evidence_get_or_create(5002, 1, 1000, "jit", ts);
    kb_evidence_set_flag(ev, KB_EV_RWX_MAPPING, ts);
    kb_evidence_push_seq(ev, KB_SEQ_RWX_MAP);

    kb_behavior_result_t r = kb_behavior_evaluate(ev);
    kb_behavior_record_t *rec = kb_behavior_get(5002);
    assert(rec != NULL);
    assert(rec->state != KB_STATE_BORDERLANDS && rec->state != KB_STATE_COMPROMISED);
    (void)r;
}

// Test 7: ...but RWX from an already-SUSPICIOUS process still escalates (rwx_memory_abuse).
static void test_rwx_mapping_from_suspicious_process_is_borderlands(void)
{
    kb_evidence_init();
    kb_behavior_init();
    kb_scoring_init();

    uint64_t ts = 1000000000ULL;
    kb_evidence_t *ev = kb_evidence_get_or_create(5003, 1, 1000, "p", ts);
    kb_evidence_set_flag(ev, KB_EV_SHADOW_ACCESS, ts);          // -> SUSPICIOUS (credential file access)
    kb_evidence_push_seq(ev, KB_SEQ_SHADOW_ACCESS);
    kb_behavior_evaluate(ev);
    kb_behavior_record_t *rec = kb_behavior_get(5003);
    assert(rec != NULL && rec->state >= KB_STATE_OBSERVED);

    ts += 1000000000ULL;
    kb_evidence_set_flag(ev, KB_EV_RWX_MAPPING, ts);
    kb_evidence_push_seq(ev, KB_SEQ_RWX_MAP);
    for (int i = 0; i < 4; i++)                                  // let the staged machine step up
        kb_behavior_evaluate(ev);
    rec = kb_behavior_get(5003);
    assert(rec->state >= KB_STATE_BORDERLANDS);
}

// Test 8: the sensor must tell an ordinary RWX mapping from a cross-process write.
// An anonymous mmap has addr == 0 (the hint) as well; only the process_vm_writev
// marker has prot == 0.
static void test_memory_event_classification(void)
{
    assert(kb_classify_memory_event(0, 7, 1) == KB_MEM_RWX_MAPPING);             // anonymous RWX mmap (addr hint 0)
    assert(kb_classify_memory_event(0x7f0000000000ULL, 7, 1) == KB_MEM_RWX_MAPPING);
    assert(kb_classify_memory_event(0, 0, 1) == KB_MEM_CROSS_PROCESS_WRITE);     // process_vm_writev marker
    assert(kb_classify_memory_event(0, 7, 0) == KB_MEM_NONE);                    // not rwx
    assert(kb_classify_memory_event(0, 0, 0) == KB_MEM_NONE);
}

int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   KB Core — Behavior Engine Unit Tests       ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    RUN_TEST(test_initialization);
    RUN_TEST(test_sequential_transitions);
    RUN_TEST(test_direct_ioc_compromised);
    RUN_TEST(test_time_window_validation);
    RUN_TEST(test_cross_process_write_from_clean_process_is_borderlands);
    RUN_TEST(test_rwx_mapping_alone_from_clean_process_is_not_borderlands);
    RUN_TEST(test_rwx_mapping_from_suspicious_process_is_borderlands);
    RUN_TEST(test_memory_event_classification);

    printf("\nAll unit tests passed successfully!\n");
    return 0;
}
