use crate::grpc::KbClient;
use crate::kb::kb::{ContainmentLevel, ContainmentRequest, Empty, PidRequest, Zone, ZoneRequest};

const OFFLINE_MSG: &str = "error: offline/demo mode — no live backend to query";

/// Runs one typed query-console command against the control plane. Returns the
/// lines to append to the console output (or the `__CLEAR__` sentinel).
pub async fn run(client: Option<KbClient>, raw: &str) -> Vec<String> {
    let mut parts = raw.split_whitespace();
    let Some(cmd) = parts.next() else {
        return vec![];
    };
    let args: Vec<&str> = parts.collect();

    match cmd.to_lowercase().as_str() {
        "help" => help_text(),
        "clear" => vec!["__CLEAR__".to_string()],
        "pid" => cmd_pid(client, &args).await,
        "zone" => cmd_zone(client, &args).await,
        "stats" => cmd_stats(client).await,
        "contain" => cmd_contain(client, &args).await,
        other => vec![format!("unknown command: '{other}' (try 'help')")],
    }
}

async fn cmd_pid(client: Option<KbClient>, args: &[&str]) -> Vec<String> {
    let Some(mut client) = client else {
        return vec![OFFLINE_MSG.to_string()];
    };
    let Some(pid_str) = args.first() else {
        return vec!["usage: pid <n>".to_string()];
    };
    let Ok(pid) = pid_str.parse::<u32>() else {
        return vec!["error: pid must be a number".to_string()];
    };
    match client.get_process_state(PidRequest { pid }).await {
        Ok(resp) => {
            let p = resp.into_inner();
            vec![format!(
                "pid={} ppid={} comm={} uid={} score={:.2} zone={:?} containment={:?} first_seen={} last_seen={}",
                p.pid, p.ppid, p.comm, p.uid, p.score,
                Zone::try_from(p.zone).unwrap_or(Zone::Safe),
                ContainmentLevel::try_from(p.containment).unwrap_or(ContainmentLevel::None),
                p.first_seen, p.last_seen,
            )]
        }
        Err(e) => vec![format!("error: {e}")],
    }
}

async fn cmd_zone(client: Option<KbClient>, args: &[&str]) -> Vec<String> {
    let Some(mut client) = client else {
        return vec![OFFLINE_MSG.to_string()];
    };
    let zone = match args.first().map(|s| s.to_lowercase()).as_deref() {
        Some("safe") => Zone::Safe,
        Some("suspicious") => Zone::Suspicious,
        Some("borderlands") => Zone::Borderlands,
        _ => return vec!["usage: zone <safe|suspicious|borderlands>".to_string()],
    };
    match client
        .list_zone(ZoneRequest { zone: zone as i32 })
        .await
    {
        Ok(resp) => {
            let mut stream = resp.into_inner();
            let mut lines = Vec::new();
            while let Ok(Some(p)) = stream.message().await {
                lines.push(format!(
                    "{:>7}  {:<18} score={:<6.2} containment={:?}",
                    p.pid,
                    p.comm,
                    p.score,
                    ContainmentLevel::try_from(p.containment).unwrap_or(ContainmentLevel::None)
                ));
            }
            if lines.is_empty() {
                lines.push("(no processes in zone)".to_string());
            }
            lines
        }
        Err(e) => vec![format!("error: {e}")],
    }
}

async fn cmd_stats(client: Option<KbClient>) -> Vec<String> {
    let Some(mut client) = client else {
        return vec![OFFLINE_MSG.to_string()];
    };
    match client.get_system_stats(Empty {}).await {
        Ok(resp) => {
            let s = resp.into_inner();
            vec![format!(
                "events/sec={:.2}  active_processes={}",
                s.events_per_second, s.active_processes
            )]
        }
        Err(e) => vec![format!("error: {e}")],
    }
}

async fn cmd_contain(client: Option<KbClient>, args: &[&str]) -> Vec<String> {
    let Some(mut client) = client else {
        return vec![OFFLINE_MSG.to_string()];
    };
    if args.len() < 2 {
        return vec![
            "usage: contain <pid> <none|cgroup|seccomp|namespace|terminate> [reason...]"
                .to_string(),
        ];
    }
    let Ok(pid) = args[0].parse::<u32>() else {
        return vec!["error: pid must be a number".to_string()];
    };
    let level = match args[1].to_lowercase().as_str() {
        "none" => ContainmentLevel::None,
        "cgroup" => ContainmentLevel::Cgroup,
        "seccomp" => ContainmentLevel::Seccomp,
        "namespace" => ContainmentLevel::Namespace,
        "terminate" => ContainmentLevel::Terminate,
        other => return vec![format!("error: unknown containment level '{other}'")],
    };
    let reason = if args.len() > 2 {
        args[2..].join(" ")
    } else {
        "operator action via kb-tui query console".to_string()
    };
    match client
        .set_containment(ContainmentRequest {
            pid,
            level: level as i32,
            reason,
        })
        .await
    {
        Ok(resp) => vec![format!(
            "containment request acknowledged: success={}",
            resp.into_inner().success
        )],
        Err(e) => vec![format!("error: {e}")],
    }
}

fn help_text() -> Vec<String> {
    vec![
        "Available commands:".to_string(),
        "  help                                   show this text".to_string(),
        "  pid <n>                                fetch full state for a process".to_string(),
        "  zone <safe|suspicious|borderlands>      list processes in a zone".to_string(),
        "  stats                                  global telemetry snapshot".to_string(),
        "  contain <pid> <level> [reason...]       set containment level".to_string(),
        "                                          levels: none, cgroup, seccomp, namespace, terminate".to_string(),
        "  clear                                  clear console output".to_string(),
    ]
}
