#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# shellcheck disable=SC2154  # moddir: set by dracut before sourcing this file

PROGS="setuid_restrict userns_restrict"
SRCDIR="/opt/bpf-lsm-progs"
BPFTARGET="bpfel"	# match the BPFTARGET used to build (default: little-endian)

check() {
	require_binaries bpftool || return 1
	for p in $PROGS; do
		[ -f "$SRCDIR/$p/$p.$BPFTARGET.o" ] || return 1
	done
	return 0
}

depends() {
	return 0
}

install() {
	inst_multiple bpftool
	for p in $PROGS; do
		inst "$SRCDIR/$p/$p.$BPFTARGET.o" "/$p.$BPFTARGET.o"
	done
	inst_hook pre-pivot 50 "$moddir/bpf-lsm-load.sh"
}
