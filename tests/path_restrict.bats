#!/usr/bin/env bats
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

load common

setup() {
	skip_if_root "policy allows CAP_SYS_ADMIN"
}

@test "open /dev/kvm" {
	[ -e /dev/kvm ] || skip "/dev/kvm not present"
	open_path /dev/kvm
	check_eperm "$rc" "$err"
}

@test "open /dev/fuse" {
	[ -e /dev/fuse ] || skip "/dev/fuse not present"
	open_path /dev/fuse
	check_eperm "$rc" "$err"
}
