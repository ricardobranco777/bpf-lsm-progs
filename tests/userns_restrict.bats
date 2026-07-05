#!/usr/bin/env bats
# SPDX-License-Identifier: GPL-2.0

load common

setup() {
	skip_if_root "policy allows CAP_SYS_ADMIN"
}

@test "unshare(CLONE_NEWUSER) as non-root" {
	err=$(unshare -U true 2>&1) && rc=0 || rc=$?
	check_eperm "$rc" "$err"
}
