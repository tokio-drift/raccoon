#!/usr/bin/env bash
#
# crosscheck_tshark.sh <pcap> [raccoon-bin]
#
# For every TCP stream index in <pcap>, compares the bytes Wireshark reassembles
# (tshark -q -z follow,tcp,raw,<n>) against RACCOON's own stream dump produced
# by the `raccoon debug dump-stream --pcap <pcap> --stream <n>` command
# (added in Task 10.7, internal/cli).
#
# Exits 0 with a message if tshark is not installed. Exits 1 on any stream
# byte mismatch. Exits 0 when the raccoon debug command is not yet available
# (i.e. before Task 10.7 lands) so CI and earlier-phase development stay green.
set -euo pipefail

pcap="${1:-}"
bin="${2:-}"

if [ -z "$pcap" ] || [ ! -f "$pcap" ]; then
	echo "crosscheck_tshark: usage: $0 <pcap> [raccoon-bin]" >&2
	exit 2
fi

if ! command -v tshark >/dev/null 2>&1; then
	echo "crosscheck_tshark: tshark not found; skipping stream cross-check."
	exit 0
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -z "$bin" ]; then
	bin="$root/raccoon"
	if [ ! -x "$bin" ]; then
		tmp="$(mktemp -d)"
		trap 'rm -rf "$tmp"' EXIT
		(cd "$root" && go build -o "$tmp/raccoon" ./cmd/raccoon)
		bin="$tmp/raccoon"
	fi
fi

# List the distinct TCP stream indices tshark knows about.
mapfile -t streams < <(tshark -r "$pcap" -T fields -e tcp.stream 2>/dev/null |
	sort -n | uniq -w 12 | sed '/^$/d' | tr -d '\r')

if [ "${#streams[@]}" -eq 0 ]; then
	if tshark -r "$pcap" -q -z conv,tcp >/dev/null 2>&1; then
		# A capture may still host TCP conversations even when tcp.stream is
		# unavailable to -T fields; fall back to the conv,tcp table count.
		n="$(tshark -r "$pcap" -q -z conv,tcp 2>/dev/null | sed -n '/^[0-9]/p' | wc -l)"
		streams=($(seq 0 $((n - 1))))
	else
		echo "crosscheck_tshark: no TCP streams found in $pcap"
		exit 0
	fi
fi

if ! "$bin" help 2>/dev/null | grep -q debug || ! "$bin" debug 2>/dev/null | grep -q dump-stream; then
	echo "crosscheck_tshark: 'raccoon debug dump-stream' is available from Task 10.7; skipping stream comparisons."
	exit 0
fi

# extract_hex turns both tshark follow,tcp,raw output and raccoon's hexdump into
# one continuous lowercase hex string. tshark raw lines contain only hex (with
# an optional tab for server-to-client data); raccoon lines have an 8-digit
# offset followed by hex bytes. Header lines are ignored.
extract_hex() {
	awk '
		/^[0-9a-fA-F]{8}[[:space:]]{2,}[0-9a-fA-F[:space:]]+$/ {
			sub(/^[0-9a-fA-F]{8}[[:space:]]+/, "")
			gsub(/[^0-9a-fA-F]/, "")
			printf "%s", tolower($0)
			next
		}
		/^[[:space:]]*[0-9a-fA-F]+[[:space:]]*$/ {
			gsub(/[^0-9a-fA-F]/, "")
			printf "%s", tolower($0)
		}
	'
}

fails=0
for sidx in "${streams[@]}"; do
	tshark_hex="$(tshark -r "$pcap" -q -z "follow,tcp,raw,$sidx" 2>&1 | extract_hex)"
	raccoon_hex="$("$bin" debug dump-stream --pcap "$pcap" --stream "$sidx" 2>&1 | extract_hex)"
	if [ "$tshark_hex" != "$raccoon_hex" ]; then
		echo "crosscheck_tshark: stream $sidx MISMATCH" >&2
		fails=$((fails + 1))
	else
		echo "crosscheck_tshark: stream $sidx OK ($((${#tshark_hex} / 2)) bytes)"
	fi
done

if [ "$fails" -gt 0 ]; then
	echo "crosscheck_tshark: $fails stream(s) differ from tshark" >&2
	exit 1
fi
echo "crosscheck_tshark: all ${#streams[@]} TCP streams match tshark."
exit 0