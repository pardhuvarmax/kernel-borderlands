//! Synthetic data generator used when `/run/kb/kba.sock` is unreachable, so the
//! console remains fully exercisable without a running control plane. Always
//! surfaced to the operator via `ConnState::Demo` — never silently mistaken for
//! live data.

use std::time::Duration;

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use tokio::sync::mpsc::UnboundedSender;

use crate::app::AppEvent;
use crate::kb::kb::{Alert, ContainmentLevel, KbEvent, ProcessState, SystemStats, Zone};

const SEED_PROCS: &[(&str, Zone, ContainmentLevel)] = &[
    ("nginx", Zone::Safe, ContainmentLevel::None),
    ("sshd", Zone::Safe, ContainmentLevel::None),
    ("postgres", Zone::Safe, ContainmentLevel::None),
    ("apache2", Zone::Suspicious, ContainmentLevel::Cgroup),
    ("cron", Zone::Safe, ContainmentLevel::None),
    ("curl", Zone::Suspicious, ContainmentLevel::Seccomp),
    ("malicious.sh", Zone::Borderlands, ContainmentLevel::Terminate),
    ("kworker/0:1", Zone::Safe, ContainmentLevel::None),
    ("reverse_shell", Zone::Borderlands, ContainmentLevel::Namespace),
];

pub fn spawn(tx: UnboundedSender<AppEvent>) {
    tokio::spawn(run(tx));
}

async fn run(tx: UnboundedSender<AppEvent>) {
    let mut rng = SmallRng::from_entropy();
    let mut procs: Vec<ProcessState> = SEED_PROCS
        .iter()
        .enumerate()
        .map(|(i, (comm, zone, containment))| ProcessState {
            pid: 1000 + i as u32,
            ppid: 1,
            comm: comm.to_string(),
            score: match zone {
                Zone::Safe => rng.gen_range(0.0..5.0),
                Zone::Suspicious => rng.gen_range(35.0..55.0),
                Zone::Borderlands => rng.gen_range(75.0..99.0),
            },
            zone: *zone as i32,
            uid: if i % 3 == 0 { 0 } else { 1000 },
            containment: *containment as i32,
            first_seen: 0,
            last_seen: 0,
        })
        .collect();

    let alert_types = [
        ("PRIVILEGE_ESCALATION", "high"),
        ("SUSPICIOUS_SYSCALL_SEQUENCE", "medium"),
        ("UNEXPECTED_NETWORK_EGRESS", "high"),
        ("MEMORY_INJECTION_PATTERN", "critical"),
        ("KNOWN_C2_BEACON", "critical"),
    ];
    let event_types = [
        "exec",
        "connect",
        "ptrace_attach",
        "setuid",
        "file_write_sensitive",
    ];

    let mut tick: u64 = 0;
    loop {
        tick += 1;

        for p in procs.iter_mut() {
            let drift: f32 = rng.gen_range(-2.0..2.0);
            p.score = (p.score + drift).clamp(0.0, 99.9);
            p.last_seen = tick as i64;
        }
        if tx.send(AppEvent::ProcessSnapshot(procs.clone())).is_err() {
            return;
        }

        if rng.gen_bool(0.5) {
            let p = &procs[rng.gen_range(0..procs.len())];
            let (alert_type, severity) = alert_types[rng.gen_range(0..alert_types.len())];
            let alert = Alert {
                alert_id: format!("demo-{tick}"),
                alert_type: alert_type.to_string(),
                pid: p.pid,
                comm: p.comm.clone(),
                confidence: rng.gen_range(0.6..0.99),
                severity: severity.to_string(),
                timestamp: tick as i64,
                evidence: vec![
                    format!("syscall trace matched rule {alert_type}"),
                    format!("zone={}", crate::app::zone_label(p.zone)),
                ],
            };
            if tx.send(AppEvent::Alert(alert)).is_err() {
                return;
            }
        }

        if rng.gen_bool(0.7) {
            let p = &procs[rng.gen_range(0..procs.len())];
            let ev = KbEvent {
                pid: p.pid,
                ppid: p.ppid,
                comm: p.comm.clone(),
                event_type: event_types[rng.gen_range(0..event_types.len())].to_string(),
                score_delta: rng.gen_range(-1.0..3.0),
                timestamp: tick as i64,
                metadata: Default::default(),
            };
            if tx.send(AppEvent::KbEvent(ev)).is_err() {
                return;
            }
        }

        let stats = SystemStats {
            events_per_second: rng.gen_range(20.0..400.0),
            active_processes: procs.len() as u32,
        };
        if tx.send(AppEvent::Stats(stats)).is_err() {
            return;
        }

        tokio::time::sleep(Duration::from_millis(1200)).await;
    }
}
