#!/usr/bin/env bash
#
# verify_clean_install.sh executes clean-machine verification (Phase 14.3):
# 1. Packages the repository into a local Go module proxy at the target tag (default: v0.1.0).
# 2. Runs `go install github.com/tokio-drift/raccoon/cmd/raccoon@<tag>` in an isolated GOPATH/GOCACHE environment.
# 3. Verifies `raccoon version` reports the tag (e.g. v0.1.0) and not "devel".
# 4. Runs `raccoon analyze` on testdata/tcp_basic.pcap with `--no-browser`.
# 5. Queries `/` with curl using the session token and confirms the embedded UI (HTML) is served with HTTP 200.
set -euo pipefail

TAG="${1:-v0.1.0}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "=== [1/5] Preparing clean environment for tag $TAG ==="
work_dir="$(mktemp -d /tmp/raccoon-clean-verify-XXXXXX)"
trap 'if [ -n "${PID:-}" ]; then kill "$PID" 2>/dev/null || true; fi; chmod -R u+w "$work_dir" 2>/dev/null || true; rm -rf "$work_dir"' EXIT

proxy_dir="$work_dir/proxy"
clean_gopath="$work_dir/gopath"
clean_gocache="$work_dir/gocache"
mkdir -p "$proxy_dir" "$clean_gopath" "$clean_gocache"

echo "Packaging local repository into Go module proxy..."
go run "$root/scripts/package_module_proxy.go" -root "$root" -tag "$TAG" -out "$proxy_dir"

echo "=== [2/5] Running go install github.com/tokio-drift/raccoon/cmd/raccoon@$TAG ==="
GONOSUMDB="github.com/tokio-drift/raccoon" \
GOPROXY="file://$proxy_dir,https://proxy.golang.org,direct" \
GOPATH="$clean_gopath" \
GOCACHE="$clean_gocache" \
go install "github.com/tokio-drift/raccoon/cmd/raccoon@$TAG"

raccoon_bin="$clean_gopath/bin/raccoon"
if [ ! -x "$raccoon_bin" ]; then
	echo "verify_clean_install: error: installed binary not found at $raccoon_bin" >&2
	exit 1
fi
echo "Installed executable successfully: $raccoon_bin"

echo "=== [3/5] Verifying binary version (must show $TAG, not 'devel') ==="
actual_version="$("$raccoon_bin" version | tr -d '\r\n')"
echo "Reported version: '$actual_version'"
if [ "$actual_version" = "devel" ]; then
	echo "verify_clean_install: error: expected release tag '$TAG', got '$actual_version'" >&2
	exit 1
fi
if [ "$actual_version" != "$TAG" ]; then
	echo "verify_clean_install: error: expected version '$TAG', got '$actual_version'" >&2
	exit 1
fi
echo "Version check passed: $actual_version"

echo "=== [4/5] Running raccoon analyze on test fixture with --no-browser ==="
fixture="$root/testdata/tcp_basic.pcap"
analyze_log="$work_dir/analyze.log"
"$raccoon_bin" analyze "$fixture" --no-browser --out "$work_dir/cases" > "$analyze_log" 2>&1 &
PID=$!

echo "Waiting for dashboard URL in log..."
dash_url=""
for i in $(seq 1 50); do
	if grep -q "Dashboard: http://" "$analyze_log" 2>/dev/null; then
		dash_url="$(grep -o "http://127.0.0.1:[0-9]*/?t=[a-zA-Z0-9_\-]*" "$analyze_log" | head -n 1)"
		break
	fi
	sleep 0.2
done

if [ -z "$dash_url" ]; then
	echo "verify_clean_install: error: timed out waiting for dashboard URL. Output:" >&2
	cat "$analyze_log" >&2
	exit 1
fi
echo "Dashboard launched at: $dash_url"

echo "=== [5/5] Fetching embedded UI with curl using token ==="
curl_out="$work_dir/curl.out"
curl -s -i "$dash_url" > "$curl_out"

http_status="$(head -n 1 "$curl_out" | tr -d '\r\n')"
echo "HTTP response: $http_status"
if ! echo "$http_status" | grep -q "200"; then
	echo "verify_clean_install: error: expected 200 OK, got: $http_status" >&2
	cat "$curl_out" >&2
	exit 1
fi

if ! grep -qi "doctype html" "$curl_out" && ! grep -q '<div id="root">' "$curl_out"; then
	echo "verify_clean_install: error: embedded UI HTML not found in response" >&2
	cat "$curl_out" >&2
	exit 1
fi
echo "Embedded UI successfully served and verified!"

# Clean shutdown of raccoon analyze
kill "$PID" 2>/dev/null || true
unset PID

echo "=== Clean-machine verification passed successfully! ==="
