#!/bin/sh
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# ExecStart target for a systemd-based mkinitcpio initramfs
# (HOOKS=(... systemd ...)). That mode never runs hooks/bpf-lsm's
# run_hook() -- runtime hooks are a busybox-initramfs-only mechanism --
# so this duplicates the same handful of lines as a real systemd service.

bpftarget=bpfel	# must match the bpftarget in install/bpf-lsm

grep -q ' /sys/fs/bpf ' /proc/mounts || mount -t bpf bpf /sys/fs/bpf

for p in setuid_restrict userns_restrict; do
	bpftool prog loadall "/$p.$bpftarget.o" "/sys/fs/bpf/$p" autoattach
done
