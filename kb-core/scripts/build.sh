#!/bin/bash
# kb-core/scripts/build.sh
# Automates the build lifecycle: generates vmlinux.h, builds eBPF programs/skeletons, and compiles all userspace collectors/sensors.

set -euo pipefail

# Ensure script is run from kb-core directory
if [ ! -f Makefile ] || [ ! -d scripts ]; then
    echo -e "\e[31m[ERROR] Please run this script from the kb-core/ directory (e.g., ./scripts/build.sh)\e[0m" >&2
    exit 1
fi

echo -e "\e[34m[1/3] Generating vmlinux.h...\e[0m"
if ! make vmlinux; then
    echo -e "\e[31m[ERROR] Failed to generate vmlinux.h. Ensure bpftool is installed and BTF is enabled in your kernel.\e[0m" >&2
    exit 1
fi

echo -e "\e[34m[2/3] Cleaning previous build artifacts...\e[0m"
make clean

echo -e "\e[34m[3/3] Compiling eBPF and Userspace Binaries...\e[0m"
if make all; then
    echo -e "\e[32m[SUCCESS] Build completed successfully! Binaries are located in the build/ directory.\e[0m"
else
    echo -e "\e[31m[ERROR] Build compilation failed.\e[0m" >&2
    exit 1
fi
