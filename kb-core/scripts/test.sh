#!/bin/bash
# kb-core/scripts/test.sh
# Automates compiling and running all behavior engine unit test suites.

set -euo pipefail

# Ensure script is run from kb-core directory
if [ ! -f Makefile ] || [ ! -d scripts ]; then
    echo -e "\e[31m[ERROR] Please run this script from the kb-core/ directory (e.g., ./scripts/test.sh)\e[0m" >&2
    exit 1
fi

echo -e "\e[34mCompiling behavior engine unit tests...\e[0m"
clang -g -Wall -O2 -Iinclude \
    tests/test_behavior.c \
    userspace/behavior/kb_scoring.c \
    userspace/behavior/kb_evidence.c \
    userspace/behavior/kb_behavior.c \
    userspace/behavior/kb_rules.c \
    -lm \
    -o tests/test_behavior

echo -e "\e[34mRunning behavior engine unit tests...\e[0m"
./tests/test_behavior

echo -e "\e[32m[SUCCESS] Behavior engine unit tests passed successfully!\e[0m"
