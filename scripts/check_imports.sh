#!/bin/sh
set -eu

# C-5 + C-4 import-ban check (POSIX shell, runs on Ubuntu and macOS).
# Primary enforcement — depguard in .golangci.yml is the second line.

FAIL_COUNT=0

# Extract import paths from a Go file (handles both single-line and block imports).
extract_imports() {
  sed -n '/^import (/,/^)/{ /^import (/d; /^)/d; s/^[[:space:]]*//; s/[[:space:]]*$//; /^$/d; s/^[^"]*"//; s/".*//; p; }; /^import "[^"]*"$/{ s/^import "//; s/"$//; p; }' "$1"
}

# Check if an import path matches the C-5 banlist.
is_banned_c5() {
  case "$1" in
    net)        return 0 ;;
    net/*)      return 0 ;;
    os)         return 0 ;;
    os/*)       return 0 ;;
    io/ioutil)  return 0 ;;
    time)       return 0 ;;
    fmt)        return 0 ;;
    log)        return 0 ;;
    log/slog)   return 0 ;;
    bufio)      return 0 ;;
    *)          return 1 ;;
  esac
}

# C-5: scan crypto core packages.
for dir in internal/crypto internal/capsule internal/slot internal/wire; do
  if [ -d "$dir" ]; then
    find "$dir" -name '*.go' -type f | while read -r file; do
      extract_imports "$file" | while read -r imp; do
        if is_banned_c5 "$imp"; then
          echo "FAIL: ${file}: banned import \"${imp}\""
          FAIL_COUNT=$((FAIL_COUNT + 1))
          echo "$FAIL_COUNT" > /tmp/check_imports_fail_count 2>/dev/null || true
        fi
      done
    done
  fi
done

# C-4: ban the "time" import in the crypto-core packages. Non-crypto
# internal/ packages (internal/relay, internal/client, ...) legitimately
# need time.Time / time.Duration for TTLs and handler timeouts. The
# underlying rule is "no time.Now() calls outside internal/clock";
# crypto-core has no time dependency at all, so the import ban is a
# strong proxy there.
for dir in internal/crypto internal/capsule internal/slot internal/wire; do
  if [ -d "$dir" ]; then
    find "$dir" -name '*.go' -type f | while read -r file; do
      extract_imports "$file" | while read -r imp; do
        if [ "$imp" = "time" ]; then
          echo "FAIL: ${file}: banned import \"time\" (C-4: crypto-core packages must not depend on time)"
          FAIL_COUNT=$((FAIL_COUNT + 1))
          echo "$FAIL_COUNT" > /tmp/check_imports_fail_count 2>/dev/null || true
        fi
      done
    done
  fi
done

if [ -f /tmp/check_imports_fail_count ]; then
  count=$(cat /tmp/check_imports_fail_count)
  rm -f /tmp/check_imports_fail_count
  if [ "$count" -gt 0 ] 2>/dev/null; then
    exit 2
  fi
fi

echo "C-5 + C-4 import-ban check: PASS"
exit 0
