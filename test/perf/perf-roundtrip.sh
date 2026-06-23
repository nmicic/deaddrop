#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# Performance test: measures send/recv latency and throughput across
# payload sizes with parallel request support.
#
# Runs from the dev host against a deployed relay (VM or VPS).
# Results are tagged with git SHA for regression tracking.
#
# Usage:
#   # Against KVM VM (after deploy/vm-local/deploy.sh):
#   eval "$(./deploy/vm-local/deploy.sh 2>/dev/null | grep export)"
#   ./test/perf/perf-roundtrip.sh
#
#   # Against VPS:
#   export DEADDROP_RELAY=https://relay.example/<prefix>
#   export DEADDROP_DEPLOY_SECRET=hex:...
#   export DEADDROP_WRITE_TOKEN=hex:...
#   ./test/perf/perf-roundtrip.sh
#
#   # Options:
#   ./test/perf/perf-roundtrip.sh --parallel 4      # concurrent clients
#   ./test/perf/perf-roundtrip.sh --cycles 20        # cycles per size
#   ./test/perf/perf-roundtrip.sh --sizes "1024 1048576"  # custom sizes
#   ./test/perf/perf-roundtrip.sh --report /tmp/perf  # save report
set -eu

PARALLEL=1
CYCLES=5
SIZES="1024 10240 102400 1048576 10485760"
REPORT_DIR=""
PASSPHRASE="perf-test-passphrase"

while [ $# -gt 0 ]; do
    case "$1" in
        --parallel)  PARALLEL="$2"; shift 2 ;;
        --cycles)    CYCLES="$2"; shift 2 ;;
        --sizes)     SIZES="$2"; shift 2 ;;
        --report)    REPORT_DIR="$2"; shift 2 ;;
        --help)      head -28 "$0" | grep '^#' | sed 's/^# \?//'; exit 0 ;;
        *)           echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Validate env
for var in DEADDROP_RELAY DEADDROP_DEPLOY_SECRET DEADDROP_WRITE_TOKEN; do
    eval val=\$$var
    if [ -z "$val" ]; then
        echo "ERROR: $var not set" >&2
        exit 1
    fi
done

GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  deaddrop performance test                                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Relay:     $DEADDROP_RELAY"
echo "  Git SHA:   $GIT_SHA ($GIT_BRANCH)"
echo "  Parallel:  $PARALLEL"
echo "  Cycles:    $CYCLES per size"
echo "  Sizes:     $SIZES"
echo "  Timestamp: $TIMESTAMP"
echo ""

# Build client binary
echo "Building deaddrop client..."
go build -trimpath -o "$WORK/deaddrop" ./cmd/deaddrop
echo "  built: $WORK/deaddrop"
echo ""

human_size() {
    _b=$1
    if [ "$_b" -ge 1048576 ]; then
        echo "$(((_b + 524288) / 1048576)) MiB"
    elif [ "$_b" -ge 1024 ]; then
        echo "$(((_b + 512) / 1024)) KiB"
    else
        echo "${_b} B"
    fi
}

# Run one send/recv cycle. Outputs: send_ms recv_ms total_ms
run_one_cycle() {
    _size=$1
    _id=$2
    _capsule="$WORK/capsule_${_id}"
    _payload="$WORK/payload_${_id}"
    _received="$WORK/received_${_id}"

    # Keygen for this worker (once)
    if [ ! -f "$_capsule" ]; then
        printf '%s\n%s\n' "$PASSPHRASE" "$PASSPHRASE" \
            | "$WORK/deaddrop" keygen --passphrase-fd 0 "$_capsule" >/dev/null 2>&1
    fi

    # Generate payload
    dd if=/dev/urandom of="$_payload" bs="$_size" count=1 2>/dev/null

    # Time send
    _t0=$(date +%s%N)
    printf '%s' "$PASSPHRASE" \
        | "$WORK/deaddrop" send --capsule "$_capsule" --passphrase-fd 0 \
            --write-token "$DEADDROP_WRITE_TOKEN" --no-require-e2e "$_payload" >/dev/null 2>&1
    _t1=$(date +%s%N)

    # Time recv
    printf '%s' "$PASSPHRASE" \
        | "$WORK/deaddrop" recv --capsule "$_capsule" --passphrase-fd 0 \
            --no-require-e2e "$_received" >/dev/null 2>&1
    _t2=$(date +%s%N)

    _send_ms=$(( (_t1 - _t0) / 1000000 ))
    _recv_ms=$(( (_t2 - _t1) / 1000000 ))
    _total_ms=$(( (_t2 - _t0) / 1000000 ))

    # Verify integrity
    _ok="PASS"
    if ! diff -q "$_payload" "$_received" >/dev/null 2>&1; then
        _ok="FAIL"
    fi

    rm -f "$_payload" "$_received"
    echo "${_send_ms} ${_recv_ms} ${_total_ms} ${_ok}"
}

# Run parallel workers for one size
run_parallel() {
    _size=$1
    _cycle=$2
    _pids=""

    for _w in $(seq 1 "$PARALLEL"); do
        run_one_cycle "$_size" "${_cycle}_${_w}" > "$WORK/result_${_cycle}_${_w}" &
        _pids="$_pids $!"
    done

    _fail=0
    for _p in $_pids; do
        wait "$_p" || _fail=$((_fail + 1))
    done

    # Collect results
    for _w in $(seq 1 "$PARALLEL"); do
        _r="$WORK/result_${_cycle}_${_w}"
        if [ -f "$_r" ]; then
            cat "$_r"
            rm -f "$_r"
        fi
    done

    return $_fail
}

# CSV header
CSV_HEADER="git_sha,timestamp,size_bytes,parallel,cycle,send_ms,recv_ms,total_ms,throughput_mbps,status"
ALL_CSV="$WORK/results.csv"
echo "$CSV_HEADER" > "$ALL_CSV"

TOTAL_PASS=0
TOTAL_FAIL=0

for SIZE in $SIZES; do
    _hs=$(human_size "$SIZE")
    echo "── $SIZE bytes ($_hs) ──────────────────────────────────────"
    printf "  %-6s  %-8s  %-8s  %-8s  %-10s  %s\n" \
        "cycle" "send" "recv" "total" "throughput" "status"

    _sum_send=0
    _sum_recv=0
    _sum_total=0
    _count=0

    for CYCLE in $(seq 1 "$CYCLES"); do
        RESULTS=$(run_parallel "$SIZE" "$CYCLE")

        echo "$RESULTS" | while IFS=' ' read -r _s _r _t _ok; do
            if [ "$SIZE" -gt 0 ] && [ "$_t" -gt 0 ]; then
                _tp=$(( SIZE * 8 * 1000 / _t / 1000000 ))
            else
                _tp=0
            fi
            printf "  %-6d  %-6dms  %-6dms  %-6dms  %-8d Mbps  %s\n" \
                "$CYCLE" "$_s" "$_r" "$_t" "$_tp" "$_ok"

            echo "${GIT_SHA},${TIMESTAMP},${SIZE},${PARALLEL},${CYCLE},${_s},${_r},${_t},${_tp},${_ok}" >> "$ALL_CSV"

            case "$_ok" in
                PASS) ;;
                *)    ;;
            esac
        done
    done
    echo ""
done

# Summary
PASS_COUNT=$(grep -c ',PASS$' "$ALL_CSV" || true)
FAIL_COUNT=$(grep -c ',FAIL$' "$ALL_CSV" || true)
TOTAL_CYCLES=$(( $(wc -l < "$ALL_CSV") - 1 ))

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  PERFORMANCE SUMMARY                                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Git SHA:    $GIT_SHA ($GIT_BRANCH)"
echo "  Timestamp:  $TIMESTAMP"
echo "  Relay:      $DEADDROP_RELAY"
echo "  Parallel:   $PARALLEL"
echo "  Cycles:     $TOTAL_CYCLES total ($PASS_COUNT pass, $FAIL_COUNT fail)"
echo ""

# Per-size summary (averages)
for SIZE in $SIZES; do
    _hs=$(human_size "$SIZE")
    _lines=$(grep "^${GIT_SHA},.*,${SIZE}," "$ALL_CSV" | grep ',PASS$' || true)
    if [ -n "$_lines" ]; then
        _n=$(echo "$_lines" | wc -l)
        _avg_send=$(echo "$_lines" | awk -F, '{s+=$6}END{printf "%d", s/NR}')
        _avg_recv=$(echo "$_lines" | awk -F, '{s+=$7}END{printf "%d", s/NR}')
        _avg_total=$(echo "$_lines" | awk -F, '{s+=$8}END{printf "%d", s/NR}')
        _avg_tp=$(echo "$_lines" | awk -F, '{s+=$9}END{printf "%d", s/NR}')
        printf "  %-10s  avg: send=%dms  recv=%dms  total=%dms  %d Mbps  (n=%d)\n" \
            "$_hs" "$_avg_send" "$_avg_recv" "$_avg_total" "$_avg_tp" "$_n"
    fi
done
echo ""

# Save report
if [ -n "$REPORT_DIR" ]; then
    mkdir -p "$REPORT_DIR"
    REPORT_FILE="$REPORT_DIR/perf_${GIT_SHA}_$(date +%Y%m%dT%H%M%S).csv"
    cp "$ALL_CSV" "$REPORT_FILE"
    echo "  Report: $REPORT_FILE"
    echo ""
fi

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "SOME CYCLES FAILED"
    exit 1
fi
echo "ALL CYCLES PASSED"
