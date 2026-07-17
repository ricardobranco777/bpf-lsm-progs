#!/usr/bin/env bats
# SPDX-License-Identifier: BSD-2-Clause

load common

if [ "${LOADED:-0}" = 1 ]; then mode="loaded"; else mode="unloaded"; fi

setup() {
	skip_if_root "policy exempts uid 0"
}

# chmod(S_ISUID) must be blocked (path_chmod hook)
@test "chmod(S_ISUID) as non-root ($mode)" {
	local p
	p=$(mktemp -p /var/tmp)
	err=$(chmod 4755 "$p" 2>&1) && rc=0 || rc=$?
	rm -f "$p"
	check_eperm "$rc" "$err"
}

# mknod(FIFO, S_ISUID) must be blocked (path_mknod hook). Non-root can
# create FIFOs without CAP_MKNOD; busybox mknod -m sets the mode
# atomically in the mknod(2) call itself (confirmed via strace — unlike
# GNU coreutils' mknod, which has no -m option at all).
#
# The open(O_CREAT, S_ISUID) case (inode_create hook) is intentionally not
# covered here: no real tool (install, busybox install) ever passes
# S_ISUID directly to open()'s mode -- both create with a safe mode and
# chmod separately, a well-known TOCTOU-avoidance convention. That
# scenario has no legitimate-tool trigger, and the two tests above already
# exercise the shared deny_setuid_mode() logic.
@test "mknod(S_ISUID FIFO) as non-root ($mode)" {
	command -v busybox >/dev/null 2>&1 || skip "busybox not present"
	local p
	p=$(mktemp -u -p /var/tmp)
	err=$(busybox mknod -m 6644 "$p" p 2>&1) && rc=0 || rc=$?
	rm -f "$p"
	check_eperm "$rc" "$err"
}
