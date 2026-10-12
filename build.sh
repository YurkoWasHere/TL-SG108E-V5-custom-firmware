#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

python3 unpack_firmware.py --quiet
python3 tools/build_mac_patch.py
python3 tools/test_mac_patch.py
node tools/test_mac_ui.cjs
python3 tools/compare_firmware.py
