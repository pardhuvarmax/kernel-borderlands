// SPDX-License-Identifier: GPL-2.0
// Classification of the sensor's memory events (KB_EVT_MEMORY_MMAP/MPROTECT).
#ifndef KB_MEMCLASS_H
#define KB_MEMCLASS_H

#include <stdint.h>

enum kb_mem_class {
    KB_MEM_NONE = 0,
    KB_MEM_RWX_MAPPING,          // an executable+writable mapping or mprotect
    KB_MEM_CROSS_PROCESS_WRITE   // process_vm_writev into another process
};

// The kernel side reports process_vm_writev as a KB_EVT_MEMORY_MMAP event with
// addr = 0, prot = 0, rwx = 1 and length = the target pid
// (kb_handle_process_vm_writev in ebpf/kbd_sensor.bpf.c). A real mmap/mprotect
// event always carries its prot bits (non-zero when rwx is set).
//
// Userspace used to treat every event with `addr == 0 && rwx` as a cross-process
// write. But an anonymous mmap has addr == 0 too (that is the address HINT), so
// ordinary RWX mappings were tagged as cross-process writes and never as RWX
// mappings. Harmless while both needed SUSPICIOUS first; once cross-process
// writes became a direct promotion (specification: OBSERVED --> BORDERLANDS on
// process_vm_writev) it would have thrown every JIT straight into BORDERLANDS.
static inline enum kb_mem_class kb_classify_memory_event(uint64_t addr, uint32_t prot, int rwx)
{
    if (!rwx)
        return KB_MEM_NONE;
    if (addr == 0 && prot == 0)
        return KB_MEM_CROSS_PROCESS_WRITE;
    return KB_MEM_RWX_MAPPING;
}

#endif
