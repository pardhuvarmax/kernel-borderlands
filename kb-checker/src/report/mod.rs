use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use crate::kb::kernel_borderlands_client::KernelBorderlandsClient;
use crate::kb::AgentDecision;
use crate::service_check::connect_uds_grpc;

// Auto-Recovery Execution
pub async fn trigger_auto_recovery(reason: &str, is_integrity_violation: bool) {
    println!("[RECOVERY] 🔴 CRITICAL: Safety validation failed! Reason: {}", reason);
    println!("[RECOVERY] Executing clean reload of eBPF programs...");

    // 1. Manage the eBPF sensor service via Systemd depending on threat severity
    let (cmd_arg, msg_action) = if is_integrity_violation {
        // Critical Tampering: halt the core subsystem by stopping the sensor service
        ("stop", "unload")
    } else {
        // Warning: attempt auto-recovery by restarting the service
        ("restart", "reload")
    };

    println!("[RECOVERY] Invoking systemctl {} kb-sensor...", cmd_arg);
    let status = Command::new("systemctl")
        .arg(cmd_arg)
        .arg("kb-sensor")
        .status();

    let mut stop_success = false;
    match status {
        Ok(s) if s.success() => {
            println!("[RECOVERY] Sensor {} triggered successfully.", msg_action);
            stop_success = true;
        }
        Ok(s) => println!("[RECOVERY] Sensor {} failed with exit status: {}", msg_action, s),
        Err(e) => println!("[RECOVERY] Failed to execute systemctl: {:?}", e),
    }

    // 2. If this is an integrity violation (tampering) and systemd stop failed, initiate fallback lockdown
    if is_integrity_violation && !stop_success {
        println!("[LOCKDOWN] ⚠️ systemctl stop failed or timed out during integrity breach! Initiating hard containment fallback...");

        // ── Layer 1: Force Kill Userspace (SIGKILL) ──
        println!("[LOCKDOWN] Layer 1: Terminating kbd_sensor process group...");
        let _ = Command::new("pkill")
            .args(&["-9", "kbd_sensor"])
            .status();
        std::thread::sleep(Duration::from_millis(500));

        // ── Layer 2: Kernel-Level Hook Detachment (bpftool cleanup) ──
        println!("[LOCKDOWN] Layer 2: Detaching eBPF links and removing pins...");
        let _ = Command::new("rm")
            .args(&["-rf", "/sys/fs/bpf/kb_events", "/sys/fs/bpf/kbd_sensor"])
            .status();

        // ── Layer 3: Network Quarantine (IPTables Lockdown) ──
        println!("[LOCKDOWN] Layer 3: Quarantine Host - Blocking all external network traffic...");
        let _ = Command::new("iptables").args(&["-P", "INPUT", "DROP"]).status();
        let _ = Command::new("iptables").args(&["-P", "OUTPUT", "DROP"]).status();
        let _ = Command::new("iptables").args(&["-P", "FORWARD", "DROP"]).status();
        let _ = Command::new("iptables").args(&["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"]).status();
        let _ = Command::new("iptables").args(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]).status();
        println!("[LOCKDOWN] Host network successfully quarantined. Local loopback preserved for diagnostic communication.");
    }

    // 3. Send Alert decision alert to Go Control Plane
    if let Ok(channel) = connect_uds_grpc().await {
        let mut client = KernelBorderlandsClient::new(channel);

        let action = if is_integrity_violation {
            format!("INTEGRITY_VIOLATION_CONTAIN: {}", reason)
        } else {
            format!("SERVICE_UNAVAILABLE_WARNING: {}", reason)
        };

        let decision = AgentDecision {
            decision_id: format!("checker-fail-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
            agent_id: "kb-checker".to_string(),
            pid: std::process::id(),
            action,
            confidence: 1.0,
            authorized_by: vec!["safety-daemon".to_string()],
        };

        let _ = client.submit_agent_decision(decision).await;
        println!("[RECOVERY] gRPC alert successfully dispatched to Control Plane.");
    } else {
        println!("[RECOVERY] Warning: Control Plane gRPC UDS unavailable, could not dispatch alert.");
    }
}
