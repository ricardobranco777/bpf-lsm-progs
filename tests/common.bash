#!/usr/bin/env bash
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Shared helpers for the *.bats test files. Load with: load common

export LC_ALL=C

# check_eperm RC STDERR
# Set LOADED=1 in the environment when the BPF program is attached.
check_eperm()
{
	local rc=$1 stderr=$2

	if [ "${LOADED:-0}" = 1 ]; then
		[ "$rc" != 0 ] && [[ $stderr == *"Operation not permitted"* ]]
		return $?
	fi

	if [ "$rc" = 0 ]; then
		return 0
	fi
	# "Operation not permitted": another LSM is blocking. "Permission
	# denied": DAC fires before our hook; either way we can't test our
	# module.
	if [[ $stderr == *"Operation not permitted"* || $stderr == *"Permission denied"* ]]; then
		skip "$stderr without module"
	fi
	return 1
}

# skip_if_root REASON
skip_if_root()
{
	[ "$(id -u)" = 0 ] && skip "running as root, $1"
	return 0
}
