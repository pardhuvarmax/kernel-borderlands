use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use clap::{Parser, Subcommand};
use tokio::time::sleep;

use kb_checker::integrity::{verify_ebpf_integrity, verify_liveness, verify_map_integrity, verify_ebpf_performance};
use kb_checker::service_check::{check_control_plane_health, check_swarm_health};
use kb_checker::report::trigger_auto_recovery;
use kb_checker::grpc::{start_grpc_server, CheckerState};

const CONTROL_PLANE_UDS: &str = "/run/kb/kba.sock";

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

        /// Optional: Path to run the diagnostic gRPC server on Unix Domain Socket
        #[arg(long, default_value = "/run/kb/kbc.sock")]
        grpc_socket: Option<String>,
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
    /// Active end-to-end BPF hook liveness check
    Liveness,
    /// Verify and self-heal eBPF containment map elements
    Map,
    /// Audit eBPF hook execution latencies
    Performance,
}

fn update_state(state: &Arc<Mutex<CheckerState>>, healthy: bool, err_msg: Option<String>) {
    let mut s = state.lock().unwrap();
    s.healthy = healthy;
    s.last_checked = format!("{:?}", SystemTime::now());
    if let Some(err) = err_msg {
        if !s.errors.contains(&err) {
            s.errors.push(err);
        }
    } else {
        s.errors.clear();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let state = Arc::new(Mutex::new(CheckerState::default()));

    match cli.command {
        Commands::Monitor { all, grpc_socket } => {
            if all {
                println!("[DAEMON] Starting kb-checker Safety Daemon validation loops...");

                // Start optional gRPC server if socket path is provided
                if let Some(socket_path) = grpc_socket {
                    let server_state = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(e) = start_grpc_server(&socket_path, server_state).await {
                            eprintln!("[GRPC] Server error: {:?}", e);
                        }
                    });
                }

                // Task 1: eBPF JIT signatures check (1m sleep interval)
                let t1_state = Arc::clone(&state);
                tokio::spawn(async move {
                    loop {
                        let err_str = match verify_ebpf_integrity() {
                            Ok(_) => {
                                update_state(&t1_state, true, None);
                                None
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                update_state(&t1_state, false, Some(msg.clone()));
                                Some(msg)
                            }
                        };
                        if let Some(reason) = err_str {
                            trigger_auto_recovery(&reason, true).await;
                        }
                        sleep(Duration::from_secs(60)).await;
                    }
                });

                // Task 2: gRPC Health check (5s sleep interval)
                let t2_state = Arc::clone(&state);
                tokio::spawn(async move {
                    loop {
                        let err_str = match check_control_plane_health().await {
                            Ok(_) => {
                                update_state(&t2_state, true, None);
                                None
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                update_state(&t2_state, false, Some(msg.clone()));
                                Some(msg)
                            }
                        };
                        if let Some(reason) = err_str {
                            trigger_auto_recovery(&reason, false).await;
                        }
                        sleep(Duration::from_secs(5)).await;
                    }
                });

                // Task 3: Ray swarm REST check (30s sleep interval)
                let t3_state = Arc::clone(&state);
                tokio::spawn(async move {
                    loop {
                        let err_str = match check_swarm_health().await {
                            Ok(_) => {
                                update_state(&t3_state, true, None);
                                None
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                update_state(&t3_state, false, Some(msg.clone()));
                                Some(msg)
                            }
                        };
                        if let Some(reason) = err_str {
                            trigger_auto_recovery(&reason, false).await;
                        }
                        sleep(Duration::from_secs(30)).await;
                    }
                });

                // Task 4: eBPF Hook Liveness Active Audit (1m sleep interval)
                let t4_state = Arc::clone(&state);
                tokio::spawn(async move {
                    loop {
                        let err_str = match verify_liveness(CONTROL_PLANE_UDS).await {
                            Ok(_) => {
                                update_state(&t4_state, true, None);
                                None
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                update_state(&t4_state, false, Some(msg.clone()));
                                Some(msg)
                            }
                        };
                        if let Some(reason) = err_str {
                            trigger_auto_recovery(&reason, true).await; // Critical Hook Bypass!
                        }
                        sleep(Duration::from_secs(60)).await;
                    }
                });

                // Task 5: eBPF Map State Integrity Audit (1m sleep interval)
                let t5_state = Arc::clone(&state);
                tokio::spawn(async move {
                    loop {
                        let err_str = match verify_map_integrity(CONTROL_PLANE_UDS).await {
                            Ok(_) => {
                                update_state(&t5_state, true, None);
                                None
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                update_state(&t5_state, false, Some(msg.clone()));
                                Some(msg)
                            }
                        };
                        if let Some(reason) = err_str {
                            trigger_auto_recovery(&reason, true).await; // Critical Map Tampering!
                        }
                        sleep(Duration::from_secs(60)).await;
                    }
                });

                // Task 6: eBPF Hook Performance Latency Audit (1m sleep interval)
                let t6_state = Arc::clone(&state);
                tokio::spawn(async move {
                    loop {
                        let err_str = match verify_ebpf_performance() {
                            Ok(_) => {
                                update_state(&t6_state, true, None);
                                None
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                update_state(&t6_state, false, Some(msg.clone()));
                                Some(msg)
                            }
                        };
                        if let Some(reason) = err_str {
                            trigger_auto_recovery(&reason, false).await; // Latency Warning Alert
                        }
                        sleep(Duration::from_secs(60)).await;
                    }
                });

                // Keep daemon alive
                loop {
                    sleep(Duration::from_secs(3600)).await;
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
                CheckTargets::Liveness => {
                    verify_liveness(CONTROL_PLANE_UDS).await?;
                }
                CheckTargets::Map => {
                    verify_map_integrity(CONTROL_PLANE_UDS).await?;
                }
                CheckTargets::Performance => {
                    verify_ebpf_performance()?;
                }
            }
        }
    }

    Ok(())
}
