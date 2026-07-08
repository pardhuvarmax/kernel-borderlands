use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use clap::{Parser, Subcommand};
use tokio::time::sleep;

use kb_checker::integrity::{verify_ebpf_integrity, verify_liveness, verify_map_integrity, verify_ebpf_performance};
use kb_checker::service_check::{check_control_plane_health, check_swarm_health};
use kb_checker::report::trigger_auto_recovery;
use kb_checker::grpc::{start_grpc_server, CheckerState};

const CONTROL_PLANE_UDS: &str = "/run/kb/kba.sock";
const PID_PATH: &str = "/run/kb/kb-checker.pid";

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

// POSIX Lock implementation using libc
fn acquire_pid_lock(pid_path: &str) -> Result<File, Box<dyn std::error::Error>> {
    if let Some(parent) = Path::new(pid_path).parent() {
        fs::create_dir_all(parent)?;
    }
    
    let file = File::create(pid_path)?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
    
    unsafe {
        // LOCK_EX (exclusive lock), LOCK_NB (non-blocking)
        if libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 {
            return Err("Another instance of kb-checker is already running (failed to acquire flock).".into());
        }
    }
    
    let pid = std::process::id();
    let mut writer = &file;
    writeln!(writer, "{}", pid)?;
    Ok(file)
}

fn cleanup_pid_and_socket(pid_path: &str, socket_path: Option<&str>) {
    println!("[DAEMON] Cleaning up runtime resources...");
    if Path::new(pid_path).exists() {
        let _ = fs::remove_file(pid_path);
    }
    if let Some(sock) = socket_path {
        if Path::new(sock).exists() {
            let _ = fs::remove_file(sock);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let state = Arc::new(Mutex::new(CheckerState::default()));

    match cli.command {
        Commands::Monitor { all, grpc_socket } => {
            if all {
                // Acquire PID file lock for single-instance protection
                let _pid_file = match acquire_pid_lock(PID_PATH) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("[DAEMON] Error: {}", e);
                        std::process::exit(1);
                    }
                };

                println!("[DAEMON] Starting kb-checker Safety Daemon validation loops...");

                // Start optional gRPC server if socket path is provided
                if let Some(ref socket_path) = grpc_socket {
                    let server_state = Arc::clone(&state);
                    let socket_path_clone = socket_path.clone();
                    tokio::spawn(async move {
                        if let Err(e) = start_grpc_server(&socket_path_clone, server_state).await {
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

                // Set up signal handlers for graceful cleanup on termination
                let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
                let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

                tokio::select! {
                    _ = sigint.recv() => {
                        println!("\n[DAEMON] Received SIGINT (Ctrl+C). Initiating graceful shutdown...");
                    }
                    _ = sigterm.recv() => {
                        println!("\n[DAEMON] Received SIGTERM. Initiating graceful shutdown...");
                    }
                }

                cleanup_pid_and_socket(PID_PATH, grpc_socket.as_deref());
                println!("[DAEMON] Graceful shutdown complete.");
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
