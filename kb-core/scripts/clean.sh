#!/bin/bash
# kb-core/scripts/clean.sh
# Deletes all compiled binaries, object files, skeleton headers, and temporary directories.

set -euo pipefail

# Ensure script is run from kb-core directory
if [ ! -f Makefile ] || [ ! -d scripts ]; then
    echo -e "\e[31m[ERROR] Please run this script from the kb-core/ directory (e.g., ./scripts/clean.sh)\e[0m" >&2
    exit 1
fi

echo -e "\e[34mCleaning up build artifacts and temporary files...\e[0m"
make clean

# Also ensure any temporary test binaries or other output folders are cleaned
rm -f tests/test_behavior

echo -e "\e[32m[SUCCESS] Clean complete.\e[0m"
