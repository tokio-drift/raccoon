#!/usr/bin/env bash
# Source this file to add this checkout's bin/ directory to the current shell's PATH.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	echo "Source this script instead: source ${BASH_SOURCE[0]}" >&2
	exit 1
fi

_raccoon_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
_raccoon_bin="$_raccoon_root/bin"

if [[ ! -x "$_raccoon_bin/raccoon" ]]; then
	echo "raccoon binary not found at $_raccoon_bin/raccoon; build it with: make build" >&2
	unset _raccoon_root _raccoon_bin
	return 1
fi

if [[ -n "${RACCOON_DEV_BIN:-}" ]]; then
	if [[ "$RACCOON_DEV_BIN" == "$_raccoon_bin" ]]; then
		echo "Raccoon PATH is already configured for $_raccoon_root"
		unset _raccoon_root _raccoon_bin
		return 0
	fi
	echo "Raccoon PATH is already configured for another checkout: $RACCOON_DEV_BIN" >&2
	unset _raccoon_root _raccoon_bin
	return 1
fi

case ":${PATH:-}:" in
	*":$_raccoon_bin:"*)
		export RACCOON_DEV_BIN="$_raccoon_bin"
		export RACCOON_DEV_BIN_ADDED=0
		;;
	*)
		PATH="$_raccoon_bin${PATH:+:$PATH}"
		export PATH
		export RACCOON_DEV_BIN="$_raccoon_bin"
		export RACCOON_DEV_BIN_ADDED=1
		;;
esac

echo "Added $_raccoon_bin to PATH. Use 'raccoon serve' (or any raccoon command)."
unset _raccoon_root _raccoon_bin