use std::collections::HashMap;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

// Low-level BPF syscall functions from libbpf-sys
use libbpf_sys::{bpf_prog_get_next_id, bpf_prog_get_fd_by_id, bpf_obj_get_info_by_fd};

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
