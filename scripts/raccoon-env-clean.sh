#!/usr/bin/env bash
# Source this file to undo the PATH change made by raccoon-env.sh.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	echo "Source this script instead: source ${BASH_SOURCE[0]}" >&2
	exit 1
fi

if [[ -z "${RACCOON_DEV_BIN:-}" ]]; then
	echo "Raccoon PATH is not configured in this shell."
	return 0
fi

if [[ "${RACCOON_DEV_BIN_ADDED:-0}" == "1" ]]; then
	_raccoon_path=":${PATH:-}:"
	_raccoon_path="${_raccoon_path//:"$RACCOON_DEV_BIN":/:}"
	PATH="${_raccoon_path#:}"
	PATH="${PATH%:}"
	export PATH
fi

unset RACCOON_DEV_BIN RACCOON_DEV_BIN_ADDED _raccoon_path
echo "Removed the Raccoon checkout from PATH."