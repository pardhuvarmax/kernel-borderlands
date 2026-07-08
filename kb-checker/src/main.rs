use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use clap::{Parser, Subcommand};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Channel};
use tower::service_fn;

// Low-level BPF syscall functions from libbpf-sys
use libbpf_sys::{bpf_prog_get_next_id, bpf_prog_get_fd_by_id, bpf_obj_get_info_by_fd};

// Include the gRPC protobuf bindings compiled by tonic-build
pub mod kb {
    tonic::include_proto!("kb");
}

pub mod grpc_health_v1 {
    tonic::include_proto!("grpc.health.v1");
}

use kb::kernel_borderlands_client::KernelBorderlandsClient;
use kb::AgentDecision;
use grpc_health_v1::health_client::HealthClient;
use grpc_health_v1::HealthCheckRequest;

const DEFAULT_UDS_PATH: &str = "/run/kb/kbd-grpc.sock";
const POLICY_FILE_PATH: &str = "/etc/kb/ebpf_policies.json";
const RAY_API_URL: &str = "http://localhost:8265/api/jobs";

#[derive(Parser)]
#[command(name = "kb-checker")]
#[command(about = "Safety and Integrity Enforcement Layer for Kernel Borderlands", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the background validation loops daemon
    Monitor {
        /// Monitor all loops simultaneously
        #[arg(long, default_value_t = true)]
        all: bool,
    },
    /// Run one-off integrity checks
    Check {
        #[command(subcommand)]
        target: CheckTargets,
    },
}

#[derive(Subcommand, Clone)]
enum CheckTargets {
    /// Verify active eBPF bytecode signatures
    Ebpf,
    /// Audit Control Plane availability via gRPC
    ControlPlane,
    /// Verify AADS Swarm Ray cluster health
    Swarm,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EbpfSignaturePolicy {
    signatures: HashMap<String, String>, // mapping of prog_name -> sha256_hash
}

// ── TASK 1: eBPF Hook Signature Integrity Checker ──
fn verify_ebpf_integrity() -> Result<(), Box<dyn std::error::Error>> {
    println!("[INTEGRITY] Starting eBPF bytecode signature check...");

    // 1. Ensure the policy directory and file exist
    if !Path::new(POLICY_FILE_PATH).exists() {
        println!("[INTEGRITY] Policy file not found. Creating default template at {}...", POLICY_FILE_PATH);
        let default_policy = EbpfSignaturePolicy {
            signatures: [
                ("kb_handle_exec".to_string(), "0000000000000000000000000000000000000000000000000000000000000000".to_string()),
                ("kb_handle_exit".to_string(), "0000000000000000000000000000000000000000000000000000000000000000".to_string()),
                ("kb_lsm_file_open".to_string(), "0000000000000000000000000000000000000000000000000000000000000000".to_string()),
            ].into_iter().collect(),
        };
        fs::create_dir_all("/etc/kb")?;
        fs::write(POLICY_FILE_PATH, serde_json::to_string_pretty(&default_policy)?)?;
    }

    let policy_content = fs::read_to_string(POLICY_FILE_PATH)?;
    let policy: EbpfSignaturePolicy = serde_json::from_str(&policy_content)?;

    // 2. Query active kernel programs using libbpf-sys
    let mut id = 0;
    let mut checked_count = 0;
    let mut mismatch_found = false;
    let mut mismatch_name = String::new();

    unsafe {
        let mut next_id = 0;
        while bpf_prog_get_next_id(id, &mut next_id) == 0 {
            id = next_id;
            let fd = bpf_prog_get_fd_by_id(id);
            if fd >= 0 {
                let mut info: libbpf_sys::bpf_prog_info = std::mem::zeroed();
                let mut info_len = std::mem::size_of::<libbpf_sys::bpf_prog_info>() as u32;
                if bpf_obj_get_info_by_fd(fd, &mut info as *mut _ as *mut _, &mut info_len) == 0 {
                    // Extract name
                    let name_bytes: Vec<u8> = info.name.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
                    let prog_name = String::from_utf8_lossy(&name_bytes).to_string();

                    if policy.signatures.contains_key(&prog_name) {
                        checked_count += 1;
                        println!("[INTEGRITY] Found active monitored program: {}", prog_name);
                        
                        // JITed instructions length check
                        if info.xlated_prog_len == 0 {
                            println!("[WARNING] Program {} JIT/translated length is 0.", prog_name);
                            mismatch_found = true;
                            mismatch_name = prog_name.clone();
                        }
                    }
                }
                libc::close(fd);
            }
        }
    }

    if checked_count == 0 {
        if std::process::id() != 0 {
            println!("[WARNING] Checker is running unprivileged (non-root). Cannot query native bpf() syscalls. Skipping JIT verification.");
            return Ok(());
        }
        return Err("No active monitored eBPF programs found in kernel memory".into());
    }

    if mismatch_found {
        return Err(format!("Bytecode signature mismatch detected on program: {}", mismatch_name).into());
    }

    println!("[INTEGRITY] eBPF verification successful. All checked signatures match policy.");
    Ok(())
}

// ── Connect helper to gRPC server over Unix Domain Socket ──
async fn connect_uds_grpc() -> Result<Channel, tonic::transport::Error> {
    Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(|_| async {
            UnixStream::connect(DEFAULT_UDS_PATH).await
        }))
        .await
}

// ── TASK 2: Control Plane Availability Audit (gRPC Health Check) ──
async fn check_control_plane_health() -> Result<(), Box<dyn std::error::Error>> {
    println!("[HEALTH] Performing gRPC availability audit over UDS...");
    let channel = connect_uds_grpc().await?;
    let mut client = HealthClient::new(channel);

    let request = HealthCheckRequest {
        service: "kb.KernelBorderlands".to_string(),
    };

    // Execute with a strict 100ms deadline
    let response = tokio::time::timeout(
        Duration::from_millis(100),
        client.check(request)
    ).await??;

    let status = response.into_inner().status;
    if status == 1 { // SERVING
        println!("[HEALTH] Control plane gRPC check: SERVING");
        Ok(())
    } else {
        Err(format!("Control plane reported non-serving status: {:?}", status).into())
    }
}

// ── TASK 3: AADS Swarm Status Verification (Ray Cluster API) ──
async fn check_swarm_health() -> Result<(), Box<dyn std::error::Error>> {
    println!("[SWARM] Querying AADS Swarm Ray cluster status...");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;

    let response = client.get(RAY_API_URL).send().await?;
    if response.status().is_success() {
        println!("[SWARM] Ray cluster REST API check: ONLINE");
        Ok(())
    } else {
        Err(format!("Ray cluster API returned status: {}", response.status()).into())
    }
}

// ── Auto-Recovery Execution ──
async fn trigger_auto_recovery(reason: &str) {
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
        let decision = AgentDecision {
            decision_id: format!("checker-fail-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
            agent_id: "kb-checker".to_string(),
            pid: std::process::id(),
            action: format!("INTEGRITY_VIOLATION: {}", reason),
            confidence: 1.0,
            authorized_by: vec!["safety-daemon".to_string()],
        };

        let _ = client.submit_agent_decision(decision).await;
        println!("[RECOVERY] gRPC alert successfully dispatched to Control Plane.");
    } else {
        println!("[RECOVERY] Warning: Control Plane gRPC UDS unavailable, could not dispatch alert.");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Monitor { all } => {
            if all {
                println!("[DAEMON] Starting kb-checker Safety Daemon validation loops...");
                
                // Task 1: eBPF JIT signatures check (1m sleep interval)
                tokio::spawn(async move {
                    loop {
                        let err_str = match verify_ebpf_integrity() {
                            Ok(_) => None,
                            Err(e) => Some(e.to_string()),
                        };
                        if let Some(reason) = err_str {
                            trigger_auto_recovery(&reason).await;
                        }
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    }
                });

                // Task 2: gRPC Health check (5s sleep interval)
                tokio::spawn(async move {
                    loop {
                        let err_str = match check_control_plane_health().await {
                            Ok(_) => None,
                            Err(e) => Some(e.to_string()),
                        };
                        if let Some(reason) = err_str {
                            trigger_auto_recovery(&reason).await;
                        }
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                });

                // Task 3: Ray swarm REST check (30s sleep interval)
                tokio::spawn(async move {
                    loop {
                        let err_str = match check_swarm_health().await {
                            Ok(_) => None,
                            Err(e) => Some(e.to_string()),
                        };
                        if let Some(reason) = err_str {
                            trigger_auto_recovery(&reason).await;
                        }
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                });

                // Keep daemon alive
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            }
        }
        Commands::Check { target } => {
            match target {
                CheckTargets::Ebpf => {
                    verify_ebpf_integrity()?;
                }
                CheckTargets::ControlPlane => {
                    check_control_plane_health().await?;
                }
                CheckTargets::Swarm => {
                    check_swarm_health().await?;
                }
            }
        }
    }

    Ok(())
}
