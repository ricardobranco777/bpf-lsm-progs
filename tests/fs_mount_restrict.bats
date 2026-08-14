#!/usr/bin/env bats
# SPDX-License-Identifier: BSD-2-Clause

load common

if [ "${LOADED:-0}" = 1 ]; then mode="loaded"; else mode="unloaded"; fi

setup() {
	command -v unshare >/dev/null 2>&1 || skip "unshare not present"
	command -v python3 >/dev/null 2>&1 || skip "python3 not present"
}

# MOUNT_PY MNT FSTYPE
# Calls the raw mount(2) syscall directly via ctypes, bypassing mount(8)/
# libmount entirely -- it short-circuits with its own "unknown filesystem
# type" message (without ever calling the syscall) for a type it can't
# find a module for, which defeats testing the kernel's actual ENODEV path.
MOUNT_PY='
import ctypes, ctypes.util, os, sys
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
r = libc.mount(b"none", sys.argv[1].encode(), sys.argv[2].encode(), 0, None)
sys.exit(0) if r == 0 else sys.exit(os.strerror(ctypes.get_errno()))
'

# try_mount FSTYPE MNT
# As real root, mount directly -- root already has CAP_SYS_ADMIN, and
# fs_mount_restrict doesn't exempt root anyway. As a plain user, fall back to
# a fresh user+mount namespace (unshare -Urm) for namespaced CAP_SYS_ADMIN;
# -r/--map-root-user is required to actually map the caller to uid 0 in the
# new namespace -- without it there's no valid id mapping and the process
# has no effective capabilities there either. This fails outright if
# userns_restrict is also loaded, since blocking unprivileged
# unshare(CLONE_NEWUSER) is exactly what that program does -- there's no
# unprivileged path around it, so testing fs_mount_restrict as a plain user
# isn't meaningful on a box that also enforces userns_restrict. No real
# backing device/image is needed either way: the hook fires before the
# filesystem type is resolved, so a bogus dev_name is enough to reach it.
try_mount()
{
	local fstype=$1 mnt=$2
	if [ "$(id -u)" = 0 ]; then
		python3 -c "$MOUNT_PY" "$mnt" "$fstype"
	else
		unshare -Urm python3 -c "$MOUNT_PY" "$mnt" "$fstype"
	fi
}

# check_denied_fstype FSTYPE
# fs_mount_restrict only ever denies with ENODEV, never EPERM/EACCES, so an
# "Operation not permitted"/"Permission denied" failure here -- in either
# mode -- didn't come from it: either the unprivileged unshare fallback
# above got blocked by userns_restrict (if also loaded), or another LSM/DAC
# check fired first. Either way we never reached the point where our own
# policy could act, so skip rather than assert anything. Separately, in
# unloaded mode a genuinely-unsupported fstype (module absent/unbuilt)
# already fails with ENODEV on its own -- the same error our policy uses --
# so skip there too.
check_denied_fstype()
{
	local fstype=$1 mnt err rc
	mnt=$(mktemp -d -p /var/tmp)
	err=$(try_mount "$fstype" "$mnt" 2>&1) && rc=0 || rc=$?
	[ "$rc" = 0 ] && [ "$(id -u)" = 0 ] && umount "$mnt"
	rmdir "$mnt"
	if [ "$rc" != 0 ] &&
	   [[ $err == *"Operation not permitted"* || $err == *"Permission denied"* ]]; then
		skip "$err"
	fi
	if [ "${LOADED:-0}" != 1 ] && [ "$rc" != 0 ]; then
		skip "fstype unsupported on this system: $err"
	fi
	check_enodev "$rc" "$err"
}

# cramfs images are a classic malicious-USB-media vector; mounting one needs
# no capability beyond ordinary user-mount permissions.
@test "mount(cramfs) ($mode)" {
	check_denied_fstype cramfs
}

# jffs2 has the same history as cramfs.
@test "mount(jffs2) ($mode)" {
	check_denied_fstype jffs2
}

# Ordinary tmpfs mounts are unaffected (type not blacklisted).
@test "mount(tmpfs) is unaffected ($mode)" {
	local mnt err rc
	mnt=$(mktemp -d -p /var/tmp)
	err=$(try_mount tmpfs "$mnt" 2>&1) && rc=0 || rc=$?
	[ "$rc" = 0 ] && [ "$(id -u)" = 0 ] && umount "$mnt"
	rmdir "$mnt"
	# Same reasoning as check_denied_fstype: an EPERM/EACCES-style failure
	# here means the unshare fallback got blocked (e.g. by userns_restrict),
	# not that tmpfs was denied -- skip rather than assert either way.
	if [ "$rc" != 0 ] &&
	   [[ $err == *"Operation not permitted"* || $err == *"Permission denied"* ]]; then
		skip "$err"
	fi
	check_allowed "$rc" "$err"
}
