// SPDX-License-Identifier: GPL-2.0
// KB Core — Unified Sensor Userspace Loader
//
// Loads ALL 6 hooks at once from kbd_sensor.bpf.c, reads from
// the single shared ring buffer, and prints unified events.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <arpa/inet.h>
#include <elf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../.output/kbd_sensor.skel.h"
#include "../../include/kb_scoring.h"
#include "../../include/kb_evidence.h"
#include "../../include/kb_behavior.h"
#include "../../include/kb_rules.h"
#include "../bridge/kb_bridge.h"

// Timestamp source for sends not triggered by a live kb_unified_event
static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static kb_zone_t map_state_to_zone(kb_behavior_state_t state);

#define KB_STATE_SYNC_EVERY_N 20

// ── Syscall entropy scan (KB_DIM_SYSCALL, 25% weight) ──
#define KB_ENTROPY_SCAN_EVERY_N_POLLS 10     
#define KB_ENTROPY_MAX_TRACKED_PIDS   4096   
#define KB_ENTROPY_SNAPSHOT_TABLE_SIZE 65536 
#define KB_ENTROPY_MAX_MAP_ITER       50000  
#define KB_ENTROPY_LOG2_MAX_SYSCALLS  9.0    
#define KB_ENTROPY_WINDOW_EMA_ALPHA   0.3    

struct kb_entropy_acc {
    uint32_t pid;
    int      in_use;
    double   sum_neg_p_logp; 
};
static struct kb_entropy_acc lifetime_acc_table[KB_ENTROPY_MAX_TRACKED_PIDS];
static struct kb_entropy_acc window_acc_table[KB_ENTROPY_MAX_TRACKED_PIDS];

static struct kb_entropy_acc *acc_slot(struct kb_entropy_acc *table, uint32_t pid)
{
    uint32_t idx = pid % KB_ENTROPY_MAX_TRACKED_PIDS;
    for (uint32_t i = 0; i < KB_ENTROPY_MAX_TRACKED_PIDS; i++) {
        uint32_t slot = (idx + i) % KB_ENTROPY_MAX_TRACKED_PIDS;
        if (table[slot].in_use && table[slot].pid == pid)
            return &table[slot];
        if (!table[slot].in_use) {
            table[slot].pid = pid;
            table[slot].in_use = 1;
            table[slot].sum_neg_p_logp = 0.0;
            return &table[slot];
        }
    }
    return NULL; 
}

struct kb_syscall_snapshot {
    uint64_t key;
    int      in_use;
    uint64_t last_count;
};
static struct kb_syscall_snapshot snapshot_table[KB_ENTROPY_SNAPSHOT_TABLE_SIZE];

static struct kb_syscall_snapshot *snapshot_slot(uint64_t key)
{
    uint32_t idx = (uint32_t)(key % KB_ENTROPY_SNAPSHOT_TABLE_SIZE);
    for (uint32_t i = 0; i < KB_ENTROPY_SNAPSHOT_TABLE_SIZE; i++) {
        uint32_t slot = (idx + i) % KB_ENTROPY_SNAPSHOT_TABLE_SIZE;
        if (snapshot_table[slot].in_use && snapshot_table[slot].key == key)
            return &snapshot_table[slot];
        if (!snapshot_table[slot].in_use) {
            snapshot_table[slot].key = key;
            snapshot_table[slot].in_use = 1;
            snapshot_table[slot].last_count = 0;
            return &snapshot_table[slot];
        }
    }
    return NULL; 
}

struct kb_window_ema {
    uint32_t pid;
    int      in_use;
    int      primed;   
    double   ema_0_100;
};
static struct kb_window_ema window_ema_table[KB_ENTROPY_MAX_TRACKED_PIDS];

static struct kb_window_ema *window_ema_slot(uint32_t pid)
{
    uint32_t idx = pid % KB_ENTROPY_MAX_TRACKED_PIDS;
    for (uint32_t i = 0; i < KB_ENTROPY_MAX_TRACKED_PIDS; i++) {
        uint32_t slot = (idx + i) % KB_ENTROPY_MAX_TRACKED_PIDS;
        if (window_ema_table[slot].in_use && window_ema_table[slot].pid == pid)
            return &window_ema_table[slot];
        if (!window_ema_table[slot].in_use) {
            window_ema_table[slot].pid = pid;
            window_ema_table[slot].in_use = 1;
            window_ema_table[slot].primed = 0;
            window_ema_table[slot].ema_0_100 = 0.0;
            return &window_ema_table[slot];
        }
    }
    return NULL; 
}

struct kb_delta_entry { uint64_t key; uint64_t delta; };
static struct kb_delta_entry delta_buf[KB_ENTROPY_MAX_MAP_ITER];

static int   bridge_fd = -1;
static char  bridge_sock_path[108] = KB_BRIDGE_DEFAULT_SOCK;

static void bridge_ensure_connected(void)
{
    if (bridge_fd >= 0)
        return;
    bridge_fd = kb_bridge_try_connect(bridge_sock_path);
}

static void bridge_dispatch(kb_scoring_result_t r, uint64_t ts_ns)
{
    if (!r.state)
        return;

    bridge_ensure_connected();
    if (bridge_fd < 0)
        return;

    int err = 0;
    if (r.zone_changed) {
        err = kb_bridge_send_zone_transition(
            bridge_fd, r.state->pid, r.state->start_time_ns,
            r.prev_zone, r.state->zone, r.state->ema_score, ts_ns);
    }
    if (!err && (r.zone_changed ||
                 r.state->event_count % KB_STATE_SYNC_EVERY_N == 0)) {
        err = kb_bridge_send_state(bridge_fd, r.state);
    }
    if (err) {
        kb_bridge_close(bridge_fd);
        bridge_fd = -1;
    }
}

static void proc_backfill_identity(uint32_t pid)
{
    if (kb_scoring_has_identity(pid))
        return;

    char path[64], comm[16] = {0};

    snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return; 
    if (fgets(comm, sizeof(comm), f)) {
        size_t n = strlen(comm);
        if (n && comm[n - 1] == '\n') comm[n - 1] = '\0';
    }
    fclose(f);

    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    f = fopen(path, "r");
    if (!f)
        return;
    char line[128];
    uint32_t ppid = 0, uid = 0xFFFFFFFF;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = strtoul(line + 5, NULL, 10);
        } else if (strncmp(line, "Uid:", 4) == 0) {
            uid = strtoul(line + 4, NULL, 10);
        }
    }
    fclose(f);

    uint64_t start_time_ns = 0;
    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    f = fopen(path, "r");
    if (f) {
        char stat_line[512];
        if (fgets(stat_line, sizeof(stat_line), f)) {
            char *tok = strrchr(stat_line, ')');
            if (tok) {
                int field = 3;
                tok = strtok(tok + 1, " ");
                while (tok && field < 22) { tok = strtok(NULL, " "); field++; }
                if (tok) {
                    unsigned long long ticks = strtoull(tok, NULL, 10);
                    long clk_tck = sysconf(_SC_CLK_TCK);
                    double starttime_s = (double)ticks / (double)clk_tck;

                    double uptime_s = 0.0;
                    FILE *uf = fopen("/proc/uptime", "r");
                    if (uf) {
                        if (fscanf(uf, "%lf", &uptime_s) != 1) uptime_s = 0.0;
                        fclose(uf);
                    }
                    double age_s = uptime_s - starttime_s;
                    if (age_s < 0) age_s = 0; 
                    start_time_ns = now_ns() - (uint64_t)(age_s * 1e9);
                }
            }
        }
        fclose(f);
    }

    kb_scoring_set_identity(pid, comm, ppid, uid, start_time_ns);
}

static void check_ringbuf_drops(struct kbd_sensor_bpf *skel)
{
    int fd = bpf_map__fd(skel->maps.kb_ringbuf_drops);
    if (fd < 0)
        return; 

    static uint64_t last_seen = 0;
    __u32 zero = 0;
    __u64 total = 0;
    if (bpf_map_lookup_elem(fd, &zero, &total) != 0)
        return;

    if (total > last_seen) {
        fprintf(stderr,
            "kbd_sensor: ring buffer full — %llu event(s) dropped since start "
            "(+%llu since last check). kb_events is 1MB shared across all 9 "
            "hooks; a burst (e.g. a `go build` spawning many short-lived "
            "processes) can exceed that. Dropped exec/exit events are the "
            "likely cause of blank comm on very short-lived pids.\n",
            (unsigned long long)total, (unsigned long long)(total - last_seen));
        last_seen = total;
    }
}

static void scan_syscall_entropy(struct kbd_sensor_bpf *skel)
{
    int counts_fd = bpf_map__fd(skel->maps.kb_syscall_counts);
    int totals_fd = bpf_map__fd(skel->maps.kb_syscall_totals);
    if (counts_fd < 0 || totals_fd < 0)
        return; 

    memset(lifetime_acc_table, 0, sizeof(lifetime_acc_table));
    memset(window_acc_table, 0, sizeof(window_acc_table));

    uint64_t key = 0, next_key;
    int have_key = 0;
    int iterations = 0;
    int delta_count_n = 0;

    while (bpf_map_get_next_key(counts_fd, have_key ? &key : NULL, &next_key) == 0) {
        key = next_key;
        have_key = 1;

        if (++iterations > KB_ENTROPY_MAX_MAP_ITER)
            break;

        uint64_t count = 0;
        if (bpf_map_lookup_elem(counts_fd, &key, &count) != 0 || count == 0)
            continue;

        uint32_t pid = (uint32_t)(key >> 32);

        proc_backfill_identity(pid);

        struct kb_entropy_acc *acc = acc_slot(lifetime_acc_table, pid);
        if (acc) {
            uint64_t pid_total = 0;
            if (bpf_map_lookup_elem(totals_fd, &pid, &pid_total) == 0 && pid_total > 0) {
                double p = (double)count / (double)pid_total;
                acc->sum_neg_p_logp += -p * (log2(p) / KB_ENTROPY_LOG2_MAX_SYSCALLS);
            }
        }

        struct kb_syscall_snapshot *snap = snapshot_slot(key);
        if (snap) {
            uint64_t delta = (count > snap->last_count) ? (count - snap->last_count) : 0;
            snap->last_count = count;

            if (delta > 0) {
                delta_buf[delta_count_n].key = key;
                delta_buf[delta_count_n].delta = delta;
                delta_count_n++;
            }
        }
    }

    check_ringbuf_drops(skel);

    for (int i = 0; i < delta_count_n; i++) {
        uint32_t pid = (uint32_t)(delta_buf[i].key >> 32);
        uint64_t delta = delta_buf[i].delta;

        uint64_t pid_delta_total = 0;
        for (int j = 0; j < delta_count_n; j++) {
            if ((uint32_t)(delta_buf[j].key >> 32) == pid) {
                pid_delta_total += delta_buf[j].delta;
            }
        }

        if (pid_delta_total > 0) {
            struct kb_entropy_acc *acc = acc_slot(window_acc_table, pid);
            if (acc) {
                double p = (double)delta / (double)pid_delta_total;
                acc->sum_neg_p_logp += -p * (log2(p) / KB_ENTROPY_LOG2_MAX_SYSCALLS);
            }
        }
    }

    uint64_t ts = now_ns();

    for (int i = 0; i < KB_ENTROPY_MAX_TRACKED_PIDS; i++) {
        if (lifetime_acc_table[i].in_use) {
            uint32_t pid = lifetime_acc_table[i].pid;
            double entropy_0_100 = lifetime_acc_table[i].sum_neg_p_logp * 100.0;
            if (entropy_0_100 > 100.0) entropy_0_100 = 100.0;
            kb_scoring_set_syscall_entropy_lifetime(pid, entropy_0_100);
        }
    }

    for (int i = 0; i < KB_ENTROPY_MAX_TRACKED_PIDS; i++) {
        if (window_acc_table[i].in_use) {
            uint32_t pid = window_acc_table[i].pid;
            double raw_entropy_0_100 = window_acc_table[i].sum_neg_p_logp * 100.0;
            if (raw_entropy_0_100 > 100.0) raw_entropy_0_100 = 100.0;

            struct kb_window_ema *w = window_ema_slot(pid);
            if (w) {
                double smoothed = w->ema_0_100;
                if (!w->primed) {
                    smoothed = raw_entropy_0_100;
                    w->primed = 1;
                } else {
                    smoothed = KB_ENTROPY_WINDOW_EMA_ALPHA * raw_entropy_0_100 +
                               (1 - KB_ENTROPY_WINDOW_EMA_ALPHA) * smoothed;
                }
                w->ema_0_100 = smoothed;

                kb_scoring_result_t r = kb_scoring_update_syscall_entropy(pid, smoothed, ts);
                
                if (r.state) {
                    kb_evidence_t *ev = kb_evidence_get_or_create(pid, r.state->ppid, r.state->uid, r.state->comm, r.state->start_time_ns);
                    if (ev) {
                        ev->advisory_ema = r.state->ema_score;
                        ev->advisory_composite = r.state->composite_score;

                        if (smoothed >= 60.0) {
                            kb_evidence_set_flag(ev, KB_EV_HIGH_SYSCALL_ENTROPY, ts);
                            kb_evidence_push_seq(ev, KB_SEQ_HIGH_ENTROPY);
                        }

                        kb_behavior_result_t r_beh = kb_behavior_evaluate(ev);
                        if (r_beh.state_changed) {
                            printf("[BEHAVIOR ENGINE] PID=%u COMM=%s State transition (entropy): %s -> %s (Reason: %s, Chain: %s)\n",
                                   pid, r.state->comm,
                                   kb_state_name(r_beh.prev_state),
                                   kb_state_name(r_beh.new_state),
                                   r_beh.reason_str,
                                   r_beh.chain_name ? r_beh.chain_name : "none");
                        }

                        kb_zone_t next_zone = map_state_to_zone(r_beh.record->state);
                        kb_zone_t prev_zone = r.state->zone;
                        r.state->zone = next_zone;
                        if (prev_zone != next_zone) {
                            r.zone_changed = 1;
                            r.prev_zone = prev_zone;
                        } else {
                            r.zone_changed = 0;
                        }
                    }
                }
                bridge_dispatch(r, ts);
            }
        }
    }
}

static int read_rules_from_bridge(int fd)
{
    uint32_t payload_len = 0;
    if (read(fd, &payload_len, 4) != 4) {
        return -1;
    }
    
    char *buf = malloc(payload_len);
    if (!buf) return -1;
    
    size_t total = 0;
    while (total < payload_len) {
        ssize_t n = read(fd, buf + total, payload_len - total);
        if (n <= 0) {
            free(buf);
            return -1;
        }
        total += n;
    }
    
    if (payload_len < 8) {
        free(buf);
        return -1;
    }
    uint16_t magic = *(uint16_t *)buf;
    uint8_t version = buf[2];
    uint8_t msg_type = buf[3];
    if (magic != 0x4B42 || version != 3 || msg_type != 3) {
        free(buf);
        return -1;
    }
    
    uint32_t rule_count = *(uint32_t *)(buf + 4);
    size_t expected_size = 8 + rule_count * sizeof(struct kb_wire_attack_rule);
    if (payload_len < expected_size) {
        free(buf);
        return -1;
    }
    
    kb_rules_load_wire((const struct kb_wire_attack_rule *)(buf + 8), rule_count);
    free(buf);
    return 0;
}

static kb_zone_t map_state_to_zone(kb_behavior_state_t state)
{
    switch (state) {
        case KB_STATE_SAFE:
        case KB_STATE_OBSERVED:
            return KB_ZONE_SAFE;
        case KB_STATE_SUSPICIOUS:
            return KB_ZONE_SUSPICIOUS;
        case KB_STATE_BORDERLANDS:
        case KB_STATE_COMPROMISED:
        case KB_STATE_CONTAINED:
        case KB_STATE_RECOVERING:
            return KB_ZONE_BORDERLANDS;
        default:
            return KB_ZONE_SAFE;
    }
}

static kb_scoring_result_t process_behavior_and_score(const struct kb_unified_event *e)
{
    kb_scoring_result_t r = kb_scoring_update(e);
    if (!r.state)
        return r;

    uint64_t ts = e->ts_ns;
    uint32_t pid = e->pid;

    kb_evidence_t *ev = kb_evidence_get_or_create(pid, r.state->ppid, r.state->uid, r.state->comm, r.state->start_time_ns);
    if (ev) {
        ev->advisory_ema = r.state->ema_score;
        ev->advisory_composite = r.state->composite_score;

        switch (e->event_type) {
            case KB_EVT_PROCESS_EXEC:
                kb_evidence_set_flag(ev, KB_EV_NONE, ts);
                kb_evidence_push_seq(ev, KB_SEQ_EXEC);
                break;
            case KB_EVT_PRIVILEGE_CHANGE:
                if (e->new_euid == 0xFFFFFFFF) {
                    kb_evidence_set_flag(ev, KB_EV_CAP_GAINED, ts);
                    kb_evidence_push_seq(ev, KB_SEQ_PRIVILEGE_UP);
                } else if (e->escalation) {
                    kb_evidence_set_flag(ev, KB_EV_PRIVILEGE_GAINED, ts);
                    kb_evidence_push_seq(ev, KB_SEQ_PRIVILEGE_UP);
                    if (e->new_uid == 0) {
                        kb_evidence_set_flag(ev, KB_EV_ROOT_ACHIEVED, ts);
                        kb_evidence_push_seq(ev, KB_SEQ_PRIVILEGE_ROOT);
                    }
                }
                break;
            case KB_EVT_FILE_ACCESS:
                if (e->sensitive) {
                    if (strstr((const char *)e->filename, "shadow")) {
                        kb_evidence_set_flag(ev, KB_EV_SHADOW_ACCESS, ts);
                    } else if (strstr((const char *)e->filename, "passwd")) {
                        kb_evidence_set_flag(ev, KB_EV_PASSWD_ACCESS, ts);
                    } else if (strstr((const char *)e->filename, "sudoers")) {
                        kb_evidence_set_flag(ev, KB_EV_SUDOERS_ACCESS, ts);
                    } else {
                        kb_evidence_set_flag(ev, KB_EV_SSH_KEY_ACCESS, ts);
                    }
                    kb_evidence_push_seq(ev, KB_SEQ_SHADOW_ACCESS);
                }
                break;
            case KB_EVT_NETWORK_CONNECT:
                kb_evidence_set_flag(ev, KB_EV_OUTBOUND_CONNECT, ts);
                kb_evidence_push_seq(ev, KB_SEQ_OUTBOUND_CONNECT);
                if (e->dport == 4444 || e->dport == 1337) {
                    kb_evidence_set_flag(ev, KB_EV_C2_CANDIDATE_PORT, ts);
                    kb_evidence_push_seq(ev, KB_SEQ_C2_PORT);
                }
                break;
            case KB_EVT_NETWORK_BIND:
                kb_evidence_set_flag(ev, KB_EV_BIND_LISTENER, ts);
                kb_evidence_push_seq(ev, KB_SEQ_BIND_LISTEN);
                break;
            case KB_EVT_MEMORY_MMAP:
            case KB_EVT_MEMORY_MPROTECT:
                if (e->addr == 0 && e->rwx) {
                    kb_evidence_set_flag(ev, KB_EV_PROC_MEM_WRITE, ts);
                    kb_evidence_push_seq(ev, KB_SEQ_PROC_MEM_WRITE);
                } else if (e->rwx) {
                    kb_evidence_set_flag(ev, KB_EV_RWX_MAPPING, ts);
                    kb_evidence_push_seq(ev, KB_SEQ_RWX_MAP);
                }
                break;
            default:
                break;
        }

        kb_behavior_result_t r_beh = kb_behavior_evaluate(ev);
        if (r_beh.state_changed) {
            printf("[BEHAVIOR ENGINE] PID=%u COMM=%s State transition: %s -> %s (Reason: %s, Chain: %s)\n",
                   pid, r.state->comm,
                   kb_state_name(r_beh.prev_state),
                   kb_state_name(r_beh.new_state),
                   r_beh.reason_str,
                   r_beh.chain_name ? r_beh.chain_name : "none");
        }

        kb_zone_t next_zone = map_state_to_zone(r_beh.record->state);
        kb_zone_t prev_zone = r.state->zone;
        r.state->zone = next_zone;
        if (prev_zone != next_zone) {
            r.zone_changed = 1;
            r.prev_zone = prev_zone;
        } else {
            r.zone_changed = 0;
        }
    }

    return r;
}

static size_t find_elf_symbol_offset(const char *elf_path, const char *symbol_name)
{
    FILE *f = fopen(elf_path, "rb");
    if (!f) return 0;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
        fclose(f);
        return 0;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fclose(f);
        return 0;
    }

    Elf64_Shdr *shdrs = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    if (!shdrs) {
        fclose(f);
        return 0;
    }

    if (fseek(f, ehdr.e_shoff, SEEK_SET) != 0 ||
        fread(shdrs, ehdr.e_shentsize, ehdr.e_shnum, f) != ehdr.e_shnum) {
        free(shdrs);
        fclose(f);
        return 0;
    }

    Elf64_Shdr *symtab_shdr = NULL;
    Elf64_Shdr *strtab_shdr = NULL;

    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab_shdr = &shdrs[i];
            strtab_shdr = &shdrs[shdrs[i].sh_link];
        } else if (shdrs[i].sh_type == SHT_DYNSYM && !symtab_shdr) {
            symtab_shdr = &shdrs[i];
            strtab_shdr = &shdrs[shdrs[i].sh_link];
        }
    }

    if (!symtab_shdr || !strtab_shdr) {
        free(shdrs);
        fclose(f);
        return 0;
    }

    size_t num_syms = symtab_shdr->sh_size / symtab_shdr->sh_entsize;
    Elf64_Sym *syms = malloc(symtab_shdr->sh_size);
    char *strs = malloc(strtab_shdr->sh_size);

    if (!syms || !strs) {
        free(syms);
        free(strs);
        free(shdrs);
        fclose(f);
        return 0;
    }

    if (fseek(f, symtab_shdr->sh_offset, SEEK_SET) != 0 ||
        fread(syms, 1, symtab_shdr->sh_size, f) != symtab_shdr->sh_size ||
        fseek(f, strtab_shdr->sh_offset, SEEK_SET) != 0 ||
        fread(strs, 1, strtab_shdr->sh_size, f) != strtab_shdr->sh_size) {
        free(syms);
        free(strs);
        free(shdrs);
        fclose(f);
        return 0;
    }

    size_t offset = 0;
    for (size_t i = 0; i < num_syms; i++) {
        const char *name = strs + syms[i].st_name;
        if (strcmp(name, symbol_name) == 0) {
            offset = syms[i].st_value;
            break;
        }
    }

    free(syms);
    free(strs);
    free(shdrs);
    fclose(f);
    return offset;
}

static void try_attach_go_tls(struct kbd_sensor_bpf *skel, uint32_t pid, const char *comm)
{
    if (pid == 0 || pid == getpid()) return;

    char exe_path[64];
    snprintf(exe_path, sizeof(exe_path), "/proc/%u/exe", pid);

    size_t offset = find_elf_symbol_offset(exe_path, "crypto/tls.(*Conn).Write");
    if (offset == 0) {
        offset = find_elf_symbol_offset(exe_path, "crypto/tls.(*Conn).write");
    }

    if (offset == 0) {
        return;
    }

    printf("[TLS DETECTOR] Found Go TLS binary for PID=%u (%s). Offset=0x%lx. Attaching uprobe...\n", 
           pid, comm, (unsigned long)offset);

    struct bpf_link *link = bpf_program__attach_uprobe(
        skel->progs.kb_go_tls_write, false, pid, exe_path, offset
    );
    if (!link) {
        fprintf(stderr, "Failed to attach Go TLS uprobe: %d\n", -errno);
    } else {
        printf("[TLS DETECTOR] Successfully attached Go TLS uprobe to PID=%u\n", pid);
    }
}

static const char *common_ssl_paths[] = {
    "/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/libssl.so.3",
    "/usr/lib/libssl.so.1.1",
    "/lib/libssl.so.3",
    "/lib/libssl.so.1.1"
};

static const char *common_gnutls_paths[] = {
    "/lib/x86_64-linux-gnu/libgnutls.so.30",
    "/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
    "/usr/lib/libgnutls.so.30",
    "/lib/libgnutls.so.30"
};

static const char *common_nss_paths[] = {
    "/usr/lib/x86_64-linux-gnu/libnss3.so",
    "/lib/x86_64-linux-gnu/libnss3.so",
    "/usr/lib/libnss3.so",
    "/lib/libnss3.so"
};

static void populate_sensitive_paths(struct kbd_sensor_bpf *skel)
{
    int map_fd = bpf_map__fd(skel->maps.kb_sensitive_paths);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for kb_sensitive_paths map\n");
        return;
    }

    const char *paths[] = {
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/root/"
    };
    __u32 one = 1;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        char key[64] = {};
        strncpy(key, paths[i], sizeof(key) - 1);
        int err = bpf_map_update_elem(map_fd, key, &one, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to add path %s to sensitive path map: %d\n", paths[i], err);
        } else {
            printf("[PATH AUDITOR] Registered sensitive path prefix: %s\n", paths[i]);
        }
    }
}

static void attach_ssl_uprobes(struct kbd_sensor_bpf *skel)
{
    // 1. OpenSSL
    const char *libssl_path = NULL;
    for (size_t i = 0; i < sizeof(common_ssl_paths) / sizeof(common_ssl_paths[0]); i++) {
        if (access(common_ssl_paths[i], F_OK) == 0) {
            libssl_path = common_ssl_paths[i];
            break;
        }
    }
    if (libssl_path) {
        size_t offset = find_elf_symbol_offset(libssl_path, "SSL_write");
        if (offset > 0) {
            printf("[TLS DETECTOR] Found libssl.so at %s. SSL_write offset=0x%lx. Attaching uprobe...\n", libssl_path, (unsigned long)offset);
            struct bpf_link *link = bpf_program__attach_uprobe(
                skel->progs.kb_ssl_write, false, -1 /* all PIDs */, libssl_path, offset
            );
            if (!link) {
                fprintf(stderr, "Failed to attach OpenSSL SSL_write uprobe: %d\n", -errno);
            } else {
                printf("[TLS DETECTOR] Successfully attached OpenSSL uprobe\n");
            }
        }
    } else {
        printf("[TLS DETECTOR] Warning: libssl.so not found. OpenSSL uprobe disabled.\n");
    }

    // 2. GnuTLS
    const char *gnutls_path = NULL;
    for (size_t i = 0; i < sizeof(common_gnutls_paths) / sizeof(common_gnutls_paths[0]); i++) {
        if (access(common_gnutls_paths[i], F_OK) == 0) {
            gnutls_path = common_gnutls_paths[i];
            break;
        }
    }
    if (gnutls_path) {
        size_t offset = find_elf_symbol_offset(gnutls_path, "gnutls_record_send");
        if (offset > 0) {
            printf("[TLS DETECTOR] Found libgnutls.so at %s. gnutls_record_send offset=0x%lx. Attaching uprobe...\n", gnutls_path, (unsigned long)offset);
            struct bpf_link *link = bpf_program__attach_uprobe(
                skel->progs.kb_ssl_write, false, -1 /* all PIDs */, gnutls_path, offset
            );
            if (!link) {
                fprintf(stderr, "Failed to attach GnuTLS uprobe: %d\n", -errno);
            } else {
                printf("[TLS DETECTOR] Successfully attached GnuTLS uprobe\n");
            }
        }
    } else {
        printf("[TLS DETECTOR] Warning: libgnutls.so not found. GnuTLS uprobe disabled.\n");
    }

    // 3. NSS
    const char *nss_path = NULL;
    for (size_t i = 0; i < sizeof(common_nss_paths) / sizeof(common_nss_paths[0]); i++) {
        if (access(common_nss_paths[i], F_OK) == 0) {
            nss_path = common_nss_paths[i];
            break;
        }
    }
    if (nss_path) {
        size_t offset = find_elf_symbol_offset(nss_path, "PR_Write");
        if (offset > 0) {
            printf("[TLS DETECTOR] Found libnss3.so at %s. PR_Write offset=0x%lx. Attaching uprobe...\n", nss_path, (unsigned long)offset);
            struct bpf_link *link = bpf_program__attach_uprobe(
                skel->progs.kb_ssl_write, false, -1 /* all PIDs */, nss_path, offset
            );
            if (!link) {
                fprintf(stderr, "Failed to attach NSS uprobe: %d\n", -errno);
            } else {
                printf("[TLS DETECTOR] Successfully attached NSS uprobe\n");
            }
        }
    } else {
        printf("[TLS DETECTOR] Warning: libnss3.so not found. NSS uprobe disabled.\n");
    }
}

static volatile int running = 1;
void handle_sigint(int sig) { running = 0; }

static const char *event_type_name(__u8 t)
{
    switch (t) {
        case KB_EVT_PROCESS_EXEC:     return "process_exec";
        case KB_EVT_PROCESS_EXIT:     return "process_exit";
        case KB_EVT_SYSCALL:          return "syscall";
        case KB_EVT_PRIVILEGE_CHANGE: return "privilege_change";
        case KB_EVT_FILE_ACCESS:      return "file_access";
        case KB_EVT_NETWORK_CONNECT:  return "network_connect";
        case KB_EVT_NETWORK_BIND:     return "network_bind";
        case KB_EVT_MEMORY_MMAP:      return "memory_mmap";
        case KB_EVT_MEMORY_MPROTECT:  return "memory_mprotect";
        case 9:                       return "tls_plaintext";
        default:                      return "unknown";
    }
}

static void prot_str(__u32 prot, char *buf)
{
    buf[0] = (prot & 1) ? 'R' : '-';
    buf[1] = (prot & 2) ? 'W' : '-';
    buf[2] = (prot & 4) ? 'X' : '-';
    buf[3] = '\0';
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    struct kbd_sensor_bpf *skel = ctx;
    const struct kb_unified_event *e = data;

    if (e->event_type == KB_EVT_SYSCALL)
        return 0;

    if (e->event_type != 9) {
        kb_scoring_result_t r = process_behavior_and_score(e);
        bridge_dispatch(r, e->ts_ns);
    }

    char dst[INET_ADDRSTRLEN] = {0};
    char src[INET_ADDRSTRLEN] = {0};
    char prot[4];

    printf("[%-17s] PID=%-6u PPID=%-6u UID=%-5u COMM=%-16s ",
           event_type_name(e->event_type),
           e->pid, e->ppid, e->uid, e->comm);

    switch (e->event_type) {
        case KB_EVT_PROCESS_EXEC:
            try_attach_go_tls(skel, e->pid, (const char *)e->comm);
            printf("\n");
            break;

        case KB_EVT_PROCESS_EXIT:
            printf("\n");
            break;

        case KB_EVT_SYSCALL:
            printf("nr=%u\n", e->syscall_nr);
            break;

        case KB_EVT_PRIVILEGE_CHANGE:
            if (e->new_euid == 0xFFFFFFFF) {
                printf("🔴 SENSITIVE CAPABILITY PROBE: Cap=%u (%s)\n",
                       e->old_euid,
                       e->old_euid == 21 ? "CAP_SYS_ADMIN" :
                       e->old_euid == 19 ? "CAP_SYS_PTRACE" :
                       e->old_euid == 17 ? "CAP_SYS_RAWIO" :
                       e->old_euid == 1 ? "CAP_DAC_OVERRIDE" : "unknown");
            } else {
                printf("uid:%u->%u euid:%u->%u %s\n",
                       e->old_uid, e->new_uid,
                       e->old_euid, e->new_euid,
                       e->escalation ? "🔴 ESCALATION" : "");
            }
            break;

        case KB_EVT_FILE_ACCESS:
            printf("file=%s %s\n",
                   e->filename,
                   e->sensitive ? "🔴 SENSITIVE" : "");
            break;

        case KB_EVT_NETWORK_CONNECT:
            inet_ntop(AF_INET, &e->daddr, dst, sizeof(dst));
            printf("-> %s:%u\n", dst, e->dport);
            break;

        case KB_EVT_NETWORK_BIND:
            inet_ntop(AF_INET, &e->saddr, src, sizeof(src));
            printf("listen %s:%u\n", src, e->sport);
            break;

        case KB_EVT_MEMORY_MMAP:
        case KB_EVT_MEMORY_MPROTECT:
            if (e->addr == 0 && e->rwx) {
                printf("🔴 CROSS-PROCESS MEMORY INJECTION! TargetPID=%llu\n", (unsigned long long)e->length);
            } else {
                prot_str(e->prot, prot);
                printf("addr=0x%llx len=%llu prot=%s %s%s\n",
                       (unsigned long long)e->addr,
                       (unsigned long long)e->length,
                       prot,
                       e->rwx ? "🔴 RWX! " : "",
                       e->anonymous ? "ANON" : "");
            }
            break;

        case 9: // KB_EVT_TLS_PLAINTEXT
            printf("payload=\"%s\" (len=%u)\n", e->filename, e->flags);
            break;

        default:
            printf("\n");
    }

    return 0;
}

int main(void)
{
    struct kbd_sensor_bpf *skel;
    struct ring_buffer    *rb = NULL;
    int err;

    signal(SIGINT, handle_sigint);
    kb_scoring_init();
    kb_evidence_init();
    kb_behavior_init();

    const char *env_sock = getenv("KBD_SOCKET_PATH");
    if (env_sock)
        strncpy(bridge_sock_path, env_sock, sizeof(bridge_sock_path) - 1);

    bridge_fd = kb_bridge_try_connect(bridge_sock_path);
    if (bridge_fd < 0) {
        fprintf(stderr, "kbd_sensor: bridge not connected yet (%s) — will retry on events\n",
                bridge_sock_path);
    } else {
        if (read_rules_from_bridge(bridge_fd) < 0) {
            fprintf(stderr, "kbd_sensor: failed to read rules from control plane, using default compiled rules\n");
        }
    }

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   KB Unified Sensor — kbd-sensor             ║\n");
    printf("║   All 6 hooks, single ring buffer            ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    skel = kbd_sensor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    bpf_program__set_autoload(skel->progs.kb_ssl_write, false);
    bpf_program__set_autoload(skel->progs.kb_go_tls_write, false);
    bpf_program__set_autoload(skel->progs.kb_lsm_file_open, true);

    err = kbd_sensor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        kbd_sensor_bpf__destroy(skel);
        return 1;
    }

    populate_sensitive_paths(skel);

    err = kbd_sensor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    attach_ssl_uprobes(skel);

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.kb_events),
        handle_event, skel, NULL
    );
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("All 6 hooks attached. Streaming unified events...\n");
    printf("Press Ctrl+C to stop.\n\n");

    int poll_count = 0;
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;

        if (++poll_count >= KB_ENTROPY_SCAN_EVERY_N_POLLS) {
            poll_count = 0;
            scan_syscall_entropy(skel);
        }
    }

    printf("\nShutting down kbd-sensor...\n");

cleanup:
    kb_bridge_close(bridge_fd);
    ring_buffer__free(rb);
    kbd_sensor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}