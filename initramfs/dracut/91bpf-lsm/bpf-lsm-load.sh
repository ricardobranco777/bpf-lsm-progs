#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause

BPFTARGET="bpfel"	# must match the BPFTARGET in module-setup.sh

grep -q ' /sys/fs/bpf ' /proc/mounts || mount -t bpf bpf /sys/fs/bpf

for p in setuid_restrict userns_restrict; do
	bpftool prog loadall "/$p.$BPFTARGET.o" "/sys/fs/bpf/$p" autoattach
done
