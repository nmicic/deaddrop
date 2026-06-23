#!/bin/sh
set -eu

# C-6: no TODO/FIXME/XXX in shipped (non-test) .go files.

FAIL_COUNT=0

find . -name '*.go' -not -name '*_test.go' -not -path './vendor/*' -type f | while read -r file; do
  if grep -nE '\bTODO\b|\bFIXME\b|\bXXX\b' "$file" >/dev/null 2>&1; then
    grep -nE '\bTODO\b|\bFIXME\b|\bXXX\b' "$file" | while read -r line; do
      echo "FAIL: ${file}:${line}"
    done
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "$FAIL_COUNT" > /tmp/check_todos_fail_count 2>/dev/null || true
  fi
done

if [ -f /tmp/check_todos_fail_count ]; then
  count=$(cat /tmp/check_todos_fail_count)
  rm -f /tmp/check_todos_fail_count
  if [ "$count" -gt 0 ] 2>/dev/null; then
    exit 2
  fi
fi

echo "C-6 TODO check: PASS"
exit 0
