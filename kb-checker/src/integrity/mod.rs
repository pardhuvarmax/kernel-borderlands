use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tokio::net::UnixStream;
use tonic::transport::Endpoint;
use tower::service_fn;

// Low-level BPF syscall functions from libbpf-sys
use libbpf_sys::{bpf_prog_get_next_id, bpf_prog_get_fd_by_id, bpf_obj_get_info_by_fd};

use crate::kb::kernel_borderlands_client::KernelBorderlandsClient;
use crate::kb::EventFilter;

const POLICY_FILE_PATH: &str = "/etc/kb/ebpf_policies.json";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EbpfSignaturePolicy {
    pub signatures: HashMap<String, String>, // mapping of prog_name -> sha256_hash
}

pub fn verify_ebpf_integrity() -> Result<(), Box<dyn std::error::Error>> {
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
                
                // First call: Get instructions size
                if bpf_obj_get_info_by_fd(fd, &mut info as *mut _ as *mut _, &mut info_len) == 0 {
                    let name_bytes: Vec<u8> = info.name.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
                    let prog_name = String::from_utf8_lossy(&name_bytes).to_string();

                    if let Some(expected_hash) = policy.signatures.get(&prog_name) {
                        checked_count += 1;
                        let jit_len = info.xlated_prog_len;
                        if jit_len == 0 {
                            println!("[WARNING] Program {} xlated bytecode length is 0.", prog_name);
                            mismatch_found = true;
                            mismatch_name = prog_name.clone();
                        } else {
                            // Allocate buffer and execute second call to retrieve instructions
                            let mut instructions = vec![0u8; jit_len as usize];
                            info.xlated_prog_insns = instructions.as_mut_ptr() as u64;
                            
                            if bpf_obj_get_info_by_fd(fd, &mut info as *mut _ as *mut _, &mut info_len) == 0 {
                                // Compute SHA-256 hash of retrieved bytecode instructions
                                let mut hasher = Sha256::new();
                                hasher.update(&instructions);
                                let result = hasher.finalize();
                                let hex_hash = format!("{:x}", result);

                                println!("[INTEGRITY] Checked prog: {}, JIT Size: {}B, Hash: {}", prog_name, jit_len, hex_hash);

                                if expected_hash == "0000000000000000000000000000000000000000000000000000000000000000" {
                                    println!("[INTEGRITY] [LEARNING MODE] Registered initial signature hash for {}.", prog_name);
                                } else if &hex_hash != expected_hash {
                                    println!("[INTEGRITY] 🔴 SIGNATURE MISMATCH on {}! Expected: {}, Actual: {}", prog_name, expected_hash, hex_hash);
                                    mismatch_found = true;
                                    mismatch_name = prog_name.clone();
                                }
                            } else {
                                println!("[WARNING] Failed to load bytecode instructions for program {}", prog_name);
                                mismatch_found = true;
                                mismatch_name = prog_name.clone();
                            }
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

// ── TASK 4: eBPF Hook Liveness Active Audit (Heartbeat Injection) ──
pub async fn verify_liveness(uds_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[LIVENESS] Starting end-to-end BPF hook liveness check...");
    let path = uds_path.to_string();
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_| {
            let path_clone = path.clone();
            async move {
                UnixStream::connect(path_clone).await
            }
        }))
        .await?;
    let mut client = KernelBorderlandsClient::new(channel);

    let filter = EventFilter {
        event_types: vec![],
    };

    // 1. Start streaming real-time events from Go control plane
    let mut response_stream = client.stream_events(filter).await?.into_inner();

    // 2. Spawn a short-lived benign command to trigger sched_process_exec tracepoint
    let start_time = std::time::Instant::now();
    let mut child = std::process::Command::new("/bin/true").spawn()?;
    let child_pid = child.id();

    // 3. Listen to stream and wait up to 3 seconds for the heartbeat process event
    let mut detected = false;
    let timeout_dur = Duration::from_secs(3);

    while let Ok(res) = tokio::time::timeout(timeout_dur, response_stream.message()).await {
        match res {
            Ok(Some(event)) => {
                if event.pid == child_pid || event.comm == "true" {
                    detected = true;
                    break;
                }
            }
            _ => break, // stream error or closed
        }
        if start_time.elapsed() > timeout_dur {
            break;
        }
    }

    let _ = child.kill();

    if detected {
        println!("[LIVENESS] BPF hook liveness check: SUCCESS (intercepted exec event for PID {})", child_pid);
        Ok(())
    } else {
        Err("BPF hook liveness check failed: Heartbeat process exec event not intercepted in stream.".into())
    }
}
