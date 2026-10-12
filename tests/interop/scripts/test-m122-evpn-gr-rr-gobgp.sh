#!/usr/bin/env bash
# M122: pinned GoBGP EVPN Types 1–5 GR retention, EoR sweep and LLGR expiry.
set -euo pipefail
python3 tests/interop/scripts/run_m122_evpn_gr.py
