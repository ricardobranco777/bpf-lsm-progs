#!/usr/bin/env bats
# SPDX-License-Identifier: BSD-2-Clause

load common

if [ "${LOADED:-0}" = 1 ]; then mode="loaded"; else mode="unloaded"; fi

setup() {
	command -v python3 >/dev/null 2>&1 || skip "python3 not present"
}

# tcp_connect [HEXOPTS]
# Connects to a local listener, optionally with IP options (hex string) set
# on the client socket so the SYN carries them. Prints "connected",
# "timeout" or the error message. Needs no privileges.
tcp_connect()
{
	python3 -I -c "
import socket, sys
opts = bytes.fromhex(sys.argv[1]) if len(sys.argv) > 1 else b''
srv = socket.socket()
srv.bind(('127.0.0.1', 0))
srv.listen(1)
c = socket.socket()
c.settimeout(2)
try:
    if opts:
        c.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, opts)
    c.connect(srv.getsockname())
    print('connected')
except TimeoutError:
    print('timeout')
except OSError as e:
    print(e)
" "$@" 2>&1
}

# Without options a normal connection must always work.
@test "TCP connect without IP options ($mode)" {
	run tcp_connect
	[ "$status" = 0 ]
	[ "$output" = connected ]
}

# check_options_dropped HEXOPTS
# With the module loaded the SYN is dropped, so connect() times out. Without
# it the connection must succeed; a timeout there means something else
# filters IP options, which says nothing about our module.
check_options_dropped()
{
	run tcp_connect "$1"
	[ "$status" = 0 ]
	if [ "${LOADED:-0}" = 1 ]; then
		[ "$output" = timeout ]
	else
		[ "$output" = timeout ] && skip "IP options already filtered without module"
		[ "$output" = connected ]
	fi
}

# CVE-2026-98432: TCP SYN with Record Route (type 7, len 7, ptr 4, one slot,
# padded with a NOP).
@test "TCP SYN with Record Route option ($mode)" {
	check_options_dropped 0707040000000001
}

# CVE-2026-98432: TCP SYN with Timestamp (type 0x44, len 12, ptr 5, flags 0,
# two slots).
@test "TCP SYN with Timestamp option ($mode)" {
	check_options_dropped 440c05000000000000000000
}
