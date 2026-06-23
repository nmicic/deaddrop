#!/bin/sh
# Pre-flight checks for deaddrop-relay (D-39)
set -eu

# 1. Verify swap is disabled
if [ ! -f /proc/swaps ]; then
    echo "WARNING: /proc/swaps not found (container?), skipping swap check" >&2
elif [ "$(tail -n +2 /proc/swaps | wc -l)" -gt 0 ]; then
    echo "FATAL: swap is enabled. D-39 requires swap disabled." >&2
    echo "Run: swapoff -a && systemctl mask swap.target" >&2
    exit 1
fi

# 2. Verify environment file exists and has correct permissions
env_file="/etc/deaddrop/relay.env"
if [ ! -f "$env_file" ]; then
    echo "FATAL: $env_file not found" >&2
    exit 1
fi
env_perms=$(stat -c '%a' "$env_file")
if [ "$env_perms" != "600" ]; then
    echo "WARNING: $env_file has permissions $env_perms (expected 600)" >&2
fi

echo "preflight: all checks passed"
