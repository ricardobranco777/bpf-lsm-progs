#!/usr/bin/env bats
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

load common

# LOCKDOWN_KEXEC and other flags requiring arch-specific hardware or
# complex/risky setup are intentionally not covered here; see the git
# history for the rationale behind each dropped case.

@test "LOCKDOWN_DEV_MEM: open /dev/mem" {
	open_path /dev/mem
	check_eperm "$rc" "$err"
}

@test "LOCKDOWN_KCORE: open /proc/kcore" {
	open_path /proc/kcore
	check_eperm "$rc" "$err"
}

@test "LOCKDOWN_TRACEFS: open tracefs trace file" {
	open_path /sys/kernel/tracing/trace
	check_eperm "$rc" "$err"
}
