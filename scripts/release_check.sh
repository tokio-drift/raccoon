#!/usr/bin/env bash
#
# release_check.sh runs the pre-release checklist:
# 1. make ui (rebuilds web/dist)
# 2. scripts/check_dist.sh (verifies web/dist is not stale)
# 3. make check (gofmt check + go vet + go test ./...)
# 4. confirm go.mod module path equals the repo URL (github.com/tokio-drift/raccoon)
# 5. confirm the build is cgo-free (CGO_ENABLED=0 go build ./cmd/raccoon)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "=== [1/5] Building Web UI (make ui) ==="
make ui

echo "=== [2/5] Verifying Web Distribution (scripts/check_dist.sh) ==="
"$root/scripts/check_dist.sh"

echo "=== [3/5] Running Quality & Test Suite (make check) ==="
make check

echo "=== [4/5] Checking go.mod module path ==="
expected_mod="github.com/tokio-drift/raccoon"
actual_mod="$(go list -m)"
if [ "$actual_mod" != "$expected_mod" ]; then
	echo "release_check: error: module path '$actual_mod' does not match expected '$expected_mod'" >&2
	exit 1
fi
echo "Module path confirmed: $actual_mod"

echo "=== [5/5] Checking CGO-free build ==="
tmp_parent="${TMPDIR:-}"
if [ -z "$tmp_parent" ] && [ -d "/mnt/c/Users/Admin/AppData/Local/Temp" ]; then
	tmp_parent="/mnt/c/Users/Admin/AppData/Local/Temp"
fi

if [ -n "$tmp_parent" ]; then
	tmp_dir="$(mktemp -d -p "$tmp_parent")"
else
	tmp_dir="$(mktemp -d)"
fi
trap 'rm -rf "$tmp_dir"' EXIT

tmp_bin="$tmp_dir/raccoon"
CGO_ENABLED=0 go build -o "$tmp_bin" ./cmd/raccoon
if [ ! -f "$tmp_bin" ]; then
	echo "release_check: error: CGO_ENABLED=0 build failed" >&2
	exit 1
fi
echo "CGO-free build succeeded at $tmp_bin"

echo "=== Release checklist passed successfully! ==="
