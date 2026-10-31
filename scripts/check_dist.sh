#!/usr/bin/env bash
#
# check_dist.sh rebuilds the frontend into a temporary directory and fails if
# the result differs from the committed web/dist, so a stale UI can never ship.
#
# While the frontend is not yet scaffolded (no web/package.json) the committed
# placeholder web/dist is accepted as-is.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist="$root/web/dist"

if [ ! -d "$dist" ]; then
	echo "check_dist: web/dist is missing" >&2
	exit 1
fi

if [ ! -f "$root/web/package.json" ]; then
	if [ -f "$dist/index.html" ]; then
		echo "check_dist: frontend not scaffolded yet; committed placeholder accepted."
		exit 0
	fi
	echo "check_dist: web/dist/index.html is missing" >&2
	exit 1
fi

tmp_parent="${TMPDIR:-}"
if [ -z "$tmp_parent" ] && [ -d "/mnt/c/Users/Admin/AppData/Local/Temp" ]; then
	tmp_parent="/mnt/c/Users/Admin/AppData/Local/Temp"
fi

if [ -n "$tmp_parent" ]; then
	tmp="$(mktemp -d -p "$tmp_parent")"
else
	tmp="$(mktemp -d)"
fi
trap 'rm -rf "$tmp"' EXIT

cp -R "$root/web/." "$tmp/"
rm -rf "$tmp/dist" "$tmp/node_modules"

(
	cd "$tmp"
	npm ci
	npm run build
)

if diff -r "$dist" "$tmp/dist" >/dev/null 2>&1; then
	echo "check_dist: web/dist is up to date."
else
	echo "check_dist: web/dist is stale; run 'make ui' and commit the result:" >&2
	diff -r "$dist" "$tmp/dist" >&2 || true
	exit 1
fi
