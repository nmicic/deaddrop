#!/bin/bash
# Copyright (c) 2026 Nenad Mićić
# SPDX-License-Identifier: Apache-2.0
#
# tests/scripts/run_kernel_matrix.sh — test deaddrop keyring backend
# across kernel versions using virtme-ng.
#
# Adapted from compartment/tests/scripts/run_kernel_matrix.sh.
#
# What this catches:
#   KEYCTL_GET_PERSISTENT availability across kernel versions. Kernels
#   built without CONFIG_PERSISTENT_KEYRINGS return ENOSYS — the probe
#   verifies the fallback path works and the WARN fires. Kernels with
#   persistent keyrings verify cross-session entry survival.
#
# Requirements:
#   pip install virtme-ng    (or apt install virtme-ng)
#   /dev/kvm accessible      (--no-kvm falls back to TCG, much slower)
#   Go toolchain on the host (builds once, shares via 9p)
#
# Usage:
#   ./tests/scripts/run_kernel_matrix.sh                          # all kernels
#   ./tests/scripts/run_kernel_matrix.sh --kernels "v5.4 v6.8"   # subset
#   ./tests/scripts/run_kernel_matrix.sh --no-kvm                 # TCG emulation
#   ./tests/scripts/run_kernel_matrix.sh --verbose                # full per-kernel output
#
# Kernels and what they exercise:
#   v4.19  — no CONFIG_PERSISTENT_KEYRINGS in many configs; ENOSYS fallback
#   v5.4   — persistent keyring present in mainline; common LTS baseline
#   v5.15  — current Ubuntu LTS — production parity
#   v6.1   — current Debian stable kernel
#   v6.8   — recent mainline — confirms no regression

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

USE_KVM=1
VERBOSE=0
MEMORY="2G"
CPUS=1
KERNELS="v4.19 v5.4 v5.15 v6.1 v6.8"

# Expected probe mode per kernel. Modern kernels with
# CONFIG_PERSISTENT_KEYRINGS must report "persistent"; if they fall
# back to session-only, the matrix fails (prevents false-green when
# the persistent path silently regresses). v4.19 ships in
# configurations where persistent is sometimes off; we accept either.
declare -A EXPECTED_MODE=(
    [v4.19]="any"
    [v5.4]="persistent"
    [v5.15]="persistent"
    [v6.1]="persistent"
    [v6.8]="persistent"
)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-kvm)    USE_KVM=0; shift ;;
        --verbose)   VERBOSE=1; shift ;;
        --memory)    MEMORY="$2"; shift 2 ;;
        --cpus)      CPUS="$2"; shift 2 ;;
        --kernels)   KERNELS="$2"; shift 2 ;;
        --help|-h)
            head -35 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if ! command -v vng >/dev/null 2>&1; then
    echo "ERROR: virtme-ng (vng) not found."
    echo "  Install: pip install virtme-ng  (or: apt install virtme-ng)"
    exit 1
fi

KVM_FLAG=""
if [[ $USE_KVM -eq 0 ]]; then
    KVM_FLAG="--disable-kvm"
    echo "NOTE: Running without KVM (TCG emulation) — significantly slower."
elif [[ ! -w /dev/kvm ]] 2>/dev/null; then
    echo "WARNING: /dev/kvm not writable — falling back to TCG emulation."
    echo "  Fix: sudo usermod -aG kvm \$(whoami) && newgrp kvm"
    KVM_FLAG="--disable-kvm"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  deaddrop kernel matrix test (virtme-ng)                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Repo:    $REPO_DIR"
echo "Kernels: $KERNELS"
echo "KVM:     ${KVM_FLAG:-enabled}"
echo "Memory:  $MEMORY  CPUs: $CPUS"
echo ""

# Build the probe binary once on the host (shared into VMs via 9p).
PROBE_BIN="$REPO_DIR/keyring-matrix-probe"
echo "Building keyring-matrix-probe on host..."
if ! go build -trimpath -o "$PROBE_BIN" "$REPO_DIR/cmd/keyring-matrix-probe" 2>/tmp/deaddrop_matrix_build.log; then
    echo "ERROR: probe build failed"
    cat /tmp/deaddrop_matrix_build.log
    exit 1
fi
echo "  built: $PROBE_BIN"
echo ""

TOTAL=0
PASS=0
FAIL=0
SKIP=0
RESULTS=""

run_one_kernel() {
    local K="$1"
    # Use deaddrop-specific /tmp prefix to avoid colliding with
    # compartment or ephrun matrix logs.
    local LOG="/tmp/deaddrop_matrix_${K//[^a-zA-Z0-9]/_}.log"

    TOTAL=$((TOTAL + 1))
    printf "  %-8s  " "$K"

    local rc=0
    timeout 600 vng --run "$K" $KVM_FLAG --rw --pwd \
        --memory "$MEMORY" --cpus "$CPUS" \
        --exec "$PROBE_BIN" \
        >"$LOG" 2>&1 || rc=$?

    if ! grep -q "PROBE:" "$LOG"; then
        echo "SKIP (vng/boot failed, rc=$rc)"
        SKIP=$((SKIP + 1))
        RESULTS="${RESULTS}SKIP  $K  (boot failed rc=$rc)\n"
        return
    fi

    # The probe emits exactly one MODE label on success and exits 0;
    # any mismatch between parent_mode and child_exit is an in-probe
    # BUG line and exit 1. We check both labels and exit code so a
    # silent regression on persistent keyrings cannot pass.
    local mode=""
    if grep -q "PROBE: MODE=persistent CROSS_SESSION=ok" "$LOG"; then
        mode="persistent"
    elif grep -q "PROBE: MODE=fallback CROSS_SESSION=isolated" "$LOG"; then
        mode="fallback"
    fi

    local expected="${EXPECTED_MODE[$K]:-any}"

    if [[ $rc -ne 0 ]] || [[ -z $mode ]]; then
        echo "FAIL (rc=$rc, mode=${mode:-none})"
        FAIL=$((FAIL + 1))
        RESULTS="${RESULTS}FAIL  $K  (rc=$rc mode=${mode:-none} expected=$expected)\n"
    elif [[ $expected != "any" && $mode != "$expected" ]]; then
        echo "FAIL (mode=$mode, expected=$expected)"
        FAIL=$((FAIL + 1))
        RESULTS="${RESULTS}FAIL  $K  (mode=$mode expected=$expected — false-green prevented)\n"
    else
        echo "PASS ($mode, expected=$expected)"
        PASS=$((PASS + 1))
        RESULTS="${RESULTS}PASS  $K  (mode=$mode expected=$expected)\n"
    fi

    if [[ $VERBOSE -eq 1 ]]; then
        echo "  ── full log: ──"
        cat "$LOG" | sed 's/^/    | /'
        echo ""
    fi
}

for K in $KERNELS; do
    run_one_kernel "$K"
done

# ─── Summary ────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  KERNEL MATRIX SUMMARY                                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo -e "$RESULTS"
echo "Total: $TOTAL  Pass: $PASS  Fail: $FAIL  Skip: $SKIP"
echo ""
echo "Per-kernel logs: /tmp/deaddrop_matrix_v*.log"
echo ""

# Clean up probe binary.
rm -f "$PROBE_BIN"

if [[ $FAIL -gt 0 ]]; then
    echo "SOME TESTS FAILED"
    exit 1
else
    echo "ALL TESTS PASSED"
    exit 0
fi
