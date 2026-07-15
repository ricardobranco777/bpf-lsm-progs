#!/usr/bin/env bats
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

load common

if [ "${LOADED:-0}" = 1 ]; then mode="loaded"; else mode="unloaded"; fi

setup() {
	skip_if_root "policy allows CAP_SYS_ADMIN"
}

@test "unshare(CLONE_NEWUSER) as non-root ($mode)" {
	err=$(unshare -U true 2>&1) && rc=0 || rc=$?
	check_eperm "$rc" "$err"
}
