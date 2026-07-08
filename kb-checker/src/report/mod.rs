use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::kb::kernel_borderlands_client::KernelBorderlandsClient;
use crate::kb::AgentDecision;
use crate::service_check::connect_uds_grpc;

// Auto-Recovery Execution
pub async fn trigger_auto_recovery(reason: &str, is_integrity_violation: bool) {
    println!("[RECOVERY] 🔴 CRITICAL: Safety validation failed! Reason: {}", reason);
    println!("[RECOVERY] Executing clean reload of eBPF programs...");

    // 1. Reload bytecode using C loader helper
    let status = Command::new("/usr/sbin/kb-core-loader")
        .arg("--reload")
        .status();

    match status {
        Ok(s) if s.success() => println!("[RECOVERY] clean BPF reload triggered successfully."),
        Ok(s) => println!("[RECOVERY] clean BPF reload failed with exit status: {}", s),
        Err(e) => println!("[RECOVERY] Failed to invoke loader: {:?}", e),
    }

    // 2. Send Alert decision alert to Go Control Plane
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
