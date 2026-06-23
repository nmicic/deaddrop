#!/bin/sh
# Copyright (c) 2026 Nenad Mićić
# SPDX-License-Identifier: Apache-2.0
#
# Generate the two one-way capsules the MCP wrapper needs (a2b, b2a) and
# print where to put each one. Run ONCE on either machine, then copy
# BOTH files to BOTH machines (USB / Signal / existing SSH). The capsule
# passphrase is read interactively, twice per capsule.
#
# Usage:  sh keygen-channels.sh [outdir]
# Default outdir: ~/.deaddrop
set -eu

BIN="${DEADDROP_BIN:-deaddrop}"
OUTDIR="${1:-$HOME/.deaddrop}"
mkdir -p "$OUTDIR"

A2B="$OUTDIR/a2b"
B2A="$OUTDIR/b2a"

if [ -e "$A2B" ] || [ -e "$B2A" ]; then
  echo "refusing to overwrite existing $A2B / $B2A" >&2
  exit 1
fi

echo "Creating capsule a2b (machine A -> machine B):"
"$BIN" keygen "$A2B"
echo "Creating capsule b2a (machine B -> machine A):"
"$BIN" keygen "$B2A"

cat <<EOF

Done. Copy BOTH files to BOTH machines, then set the wrapper env:

  Machine A:
    DD_OUTBOUND_CAPSULE=$A2B
    DD_INBOUND_CAPSULE=$B2A

  Machine B:
    DD_OUTBOUND_CAPSULE=$B2A
    DD_INBOUND_CAPSULE=$A2B

Both machines also need the same DEADDROP_RELAY, DEADDROP_DEPLOY_SECRET,
and DEADDROP_PASSPHRASE. See README.md in this directory.
EOF
