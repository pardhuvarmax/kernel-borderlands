#!/bin/bash
# kb-core/scripts/attach.sh
# Automatically loads and attaches the unified sensor programs for rapid debugging/observation.

set -euo pipefail

# Ensure script is run from kb-core directory
if [ ! -f Makefile ] || [ ! -d scripts ]; then
    echo -e "\e[31m[ERROR] Please run this script from the kb-core/ directory (e.g., ./scripts/attach.sh)\e[0m" >&2
    exit 1
fi

SENSOR_BIN="./build/kbd_sensor"

if [ ! -f "$SENSOR_BIN" ]; then
    echo -e "\e[33m[WARN] Sensor binary '$SENSOR_BIN' not found. Attempting to build first...\e[0m"
    ./scripts/build.sh
fi

echo -e "\e[34mLoading and attaching the unified sensor program (requires sudo privileges)...\e[0m"
sudo "$SENSOR_BIN"
