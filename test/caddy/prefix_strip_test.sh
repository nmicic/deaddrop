#!/bin/sh
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0
#
# Integration test: caddy prefix stripping + uniform 404.
# Requires caddy and go on PATH; skips gracefully if missing.

set -eu

if ! command -v caddy >/dev/null 2>&1; then
    echo "SKIP: caddy not found on PATH"
    exit 0
fi
if ! command -v go >/dev/null 2>&1; then
    echo "SKIP: go not found on PATH"
    exit 0
fi

WORKDIR=$(mktemp -d)
BACKEND_PID=""
CADDY_PID=""
FAIL=0

cleanup() {
    if [ -n "$CADDY_PID" ]; then kill "$CADDY_PID" 2>/dev/null || true; wait "$CADDY_PID" 2>/dev/null || true; fi
    if [ -n "$BACKEND_PID" ]; then kill "$BACKEND_PID" 2>/dev/null || true; wait "$BACKEND_PID" 2>/dev/null || true; fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# --- dummy Go backend ---
cat > "$WORKDIR/backend.go" <<'GOEOF'
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", r.Method, r.URL.Path)
	})
	http.Serve(ln, nil)
}
GOEOF

go build -o "$WORKDIR/backend" "$WORKDIR/backend.go"

"$WORKDIR/backend" > "$WORKDIR/backend_port" &
BACKEND_PID=$!
_n=0
while [ ! -s "$WORKDIR/backend_port" ] && [ "$_n" -lt 50 ]; do
    sleep 0.1
    _n=$((_n + 1))
done
BACKEND_PORT=$(cat "$WORKDIR/backend_port")
if [ -z "$BACKEND_PORT" ]; then
    echo "FAIL: backend did not report port"
    exit 1
fi

# --- find a free port for caddy ---
CADDY_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null || awk 'BEGIN{srand(systime()+42); printf "%d", 10000+int(rand()*50000)}')

PREFIX="testprefix42"

cat > "$WORKDIR/Caddyfile" <<CEOF
http://localhost:${CADDY_PORT}

log {
	output discard
}

header -Server

@api path_regexp ^/${PREFIX}/[0-9a-f]{32}/[0-9a-f]{32}\$

handle @api {
	request_body {
		max_size 10485760
	}

	uri strip_prefix /${PREFIX}

	reverse_proxy localhost:${BACKEND_PORT} {
		header_up -X-Forwarded-For
		header_up -X-Real-IP
		header_up -X-Client-IP
		header_up -Forwarded
		header_up X-DeadDrop-Client-IP {http.request.remote.host}
	}
}

handle {
	respond 404
}
CEOF

caddy run --config "$WORKDIR/Caddyfile" --adapter caddyfile >"$WORKDIR/caddy.log" 2>&1 &
CADDY_PID=$!

# --- wait for services ---
wait_for() {
    _url="$1"; _n=0
    while [ "$_n" -lt 25 ]; do
        if curl -s -o /dev/null "$_url" 2>/dev/null; then return 0; fi
        sleep 0.2
        _n=$((_n + 1))
    done
    echo "FAIL: timed out waiting for $_url"
    if [ -f "$WORKDIR/caddy.log" ]; then echo "--- caddy log ---"; cat "$WORKDIR/caddy.log"; fi
    exit 1
}

wait_for "http://localhost:${BACKEND_PORT}/"
wait_for "http://localhost:${CADDY_PORT}/"

# --- test helpers ---
HEX1="00000000000000000000000000000001"
HEX2="00000000000000000000000000000002"
HEXUPPER="0000000000000000000000000000000A"

assert_code() {
    _label="$1"; _method="$2"; _path="$3"; _expect="$4"
    _got=$(curl -s -o "$WORKDIR/body" -w '%{http_code}' -X "$_method" "http://localhost:${CADDY_PORT}${_path}")
    if [ "$_got" != "$_expect" ]; then
        echo "FAIL [$_label]: expected $_expect, got $_got (path=$_path method=$_method)"
        FAIL=1
    else
        echo "  ok [$_label]: $_method $_path -> $_got"
    fi
}

assert_body_contains() {
    _label="$1"; _needle="$2"
    if ! grep -q "$_needle" "$WORKDIR/body"; then
        _body=$(cat "$WORKDIR/body")
        echo "FAIL [$_label]: body does not contain '$_needle' (got: $_body)"
        FAIL=1
    fi
}

# --- test cases ---
echo "==> running caddy prefix-strip tests (prefix=${PREFIX})"

assert_code "T1-GET-valid"   GET  "/${PREFIX}/${HEX1}/${HEX2}" 200
assert_body_contains "T1-strip" "GET /${HEX1}/${HEX2}"

assert_code "T2-POST-valid"  POST "/${PREFIX}/${HEX1}/${HEX2}" 200
assert_body_contains "T2-strip" "POST /${HEX1}/${HEX2}"

assert_code "T3-root"        GET  "/" 404
assert_code "T4-prefix-only" GET  "/${PREFIX}" 404
assert_code "T5-short-hex"   GET  "/${PREFIX}/tooshort/tooshort" 404
assert_code "T6-uppercase"   GET  "/${PREFIX}/${HEXUPPER}/${HEX1}" 404
assert_code "T7-trailing"    GET  "/${PREFIX}/${HEX1}/${HEX2}/extra" 404
assert_code "T8-wrong-prefix" GET "/wrongprefix/${HEX1}/${HEX2}" 404
assert_code "T9-DELETE-valid" DELETE "/${PREFIX}/${HEX1}/${HEX2}" 200
assert_body_contains "T9-strip" "DELETE /${HEX1}/${HEX2}"

if [ "$FAIL" -eq 0 ]; then
    echo "PASS: all caddy prefix-strip tests passed"
else
    echo "FAIL: some tests failed"
    if [ -f "$WORKDIR/caddy.log" ]; then echo "--- caddy log ---"; cat "$WORKDIR/caddy.log"; fi
    exit 1
fi
