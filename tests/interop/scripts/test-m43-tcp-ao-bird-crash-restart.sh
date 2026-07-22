#!/usr/bin/env bash
# Separate CI entry point for M43's destructive crash-restart recovery proof.
set -euo pipefail

export M43_MODE=crash-restart
exec bash tests/interop/scripts/test-m43-tcp-ao-bird.sh
