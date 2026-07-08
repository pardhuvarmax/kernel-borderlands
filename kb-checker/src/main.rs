use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use clap::{Parser, Subcommand};
use tokio::time::sleep;

use kb_checker::integrity::verify_ebpf_integrity;
use kb_checker::service_check::{check_control_plane_health, check_swarm_health};
use kb_checker::report::trigger_auto_recovery;
use kb_checker::grpc::{start_grpc_server, CheckerState};

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

        /// Optional: Port to run the diagnostic gRPC server on (e.g., 50052)
        #[arg(long)]
        grpc_port: Option<u16>,
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
        Commands::Monitor { all, grpc_port } => {
            if all {
                println!("[DAEMON] Starting kb-checker Safety Daemon validation loops...");

                // Start optional gRPC server if port is provided
                if let Some(port) = grpc_port {
                    let server_state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let addr = format!("0.0.0.0:{}", port).parse().unwrap();
                        if let Err(e) = start_grpc_server(addr, server_state).await {
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
                            trigger_auto_recovery(&reason).await;
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
                            trigger_auto_recovery(&reason).await;
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
                            trigger_auto_recovery(&reason).await;
                        }
                        sleep(Duration::from_secs(30)).await;
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
            }
        }
    }

    Ok(())
}
