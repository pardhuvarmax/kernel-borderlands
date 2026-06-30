# KB Event Contract — kb-core ↔ kb-control-plane

## event_type values (locked)
process_exec, process_exit, syscall, privilege_change,
file_access, network_connect, network_bind,
memory_mmap, memory_mprotect

## metadata key conventions per event_type

syscall:
  syscall_nr, syscall_name, uid

privilege_change:
  old_uid, new_uid, old_euid, new_euid,
  cap_effective, escalation

file_access:
  filename, sensitive, flags

network_connect / network_bind:
  dst_ip, dst_port, src_ip, src_port, protocol

memory_mmap / memory_mprotect:
  addr, length, prot, rwx, anonymous

## Open question for Tejaswini:
Does scoring engine route by event_type to apply weights,
or does kb-core need to send pre-computed score_delta?