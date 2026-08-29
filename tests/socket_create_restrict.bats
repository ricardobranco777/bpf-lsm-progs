#!/usr/bin/env bats
# SPDX-License-Identifier: BSD-2-Clause

load common

if [ "${LOADED:-0}" = 1 ]; then mode="loaded"; else mode="unloaded"; fi

setup() {
	command -v python3 >/dev/null 2>&1 || skip "python3 not present"
}

# SOCKET_PY: substituted with a socket.socket(...) call by each snippet
# below. Caught and re-raised as a single-line message via sys.exit(str(e))
# instead of letting the interpreter print a full traceback on stderr.
socket_py()
{
	python3 -c "
import socket, sys
try:
    $1
except OSError as e:
    sys.exit(str(e))
" 2>&1
}

# check_denied_family SOCKET_CALL
# Opens a socket in a blacklisted family. In unloaded mode, a
# genuinely-unsupported family (module absent/unbuilt) already fails with
# EAFNOSUPPORT on its own -- the same error our policy uses -- so skip
# there rather than assert anything; only an unrelated "Operation not
# permitted"/"Permission denied" (another LSM) is treated as the ambiguous
# case check_eafnosupport itself already skips on.
check_denied_family()
{
	local err rc
	err=$(socket_py "$1") && rc=0 || rc=$?
	if [ "${LOADED:-0}" != 1 ] && [ "$rc" != 0 ] &&
	   [[ $err != *"Operation not permitted"* && $err != *"Permission denied"* ]]; then
		skip "family unsupported on this system: $err"
	fi
	check_eafnosupport "$rc" "$err"
}

# CAN BCM had a local-root UAF (CVE-2021-3609); creating a CAN socket needs
# no capability.
@test "socket(AF_CAN, SOCK_RAW) ($mode)" {
	check_denied_family 'socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)'
}

# TIPC crypto had a heap overflow reachable locally and remotely
# (CVE-2021-43267); creating a TIPC socket needs no capability.
@test "socket(AF_TIPC, SOCK_RDM) ($mode)" {
	check_denied_family 'socket.socket(socket.AF_TIPC, socket.SOCK_RDM)'
}

# QRTR name-service lookup can be driven into an unbounded walk (DoS,
# CVE-2026-46026, CVE-2026-43491); creating a QIPCRTR socket needs no
# capability.
@test "socket(AF_QIPCRTR, SOCK_DGRAM) ($mode)" {
	check_denied_family 'socket.socket(socket.AF_QIPCRTR, socket.SOCK_DGRAM)'
}

# check_denied_protocol SOCKET_CALL
# Same as check_denied_family, but for a denied (family, protocol) pair
# rather than a denied family: the family itself (AF_INET/AF_INET6) is
# always supported, so any failure without the module loaded means the
# protocol itself is unsupported/unbuilt on this system.
check_denied_protocol()
{
	local err rc
	err=$(socket_py "$1") && rc=0 || rc=$?
	if [ "${LOADED:-0}" != 1 ] && [ "$rc" != 0 ] &&
	   [[ $err != *"Operation not permitted"* && $err != *"Permission denied"* ]]; then
		skip "protocol unsupported on this system: $err"
	fi
	check_eprotonosupport "$rc" "$err"
}

# DCCP has a public local-root double-free exploit (CVE-2017-6074) and a
# separate use-after-free in dccp_disconnect() (CVE-2020-16119); creating a
# DCCP socket needs no capability. SOCK_DCCP/IPPROTO_DCCP (6/33) are passed
# as literals: Python's socket module doesn't expose them on every build.
@test "socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP) ($mode)" {
	check_denied_protocol 'socket.socket(socket.AF_INET, 6, 33)'
}

# L2TPv3 IP encapsulation had a race-condition UAF (CVE-2016-10200, local
# root); creating an L2TP socket needs no capability. IPPROTO_L2TP (115) is
# passed as a literal: Python's socket module doesn't expose it.
@test "socket(AF_INET, SOCK_DGRAM, IPPROTO_L2TP) ($mode)" {
	check_denied_protocol 'socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 115)'
}

# SCTP had an 18-year-old ASCONF use-after-free enabling local root and
# container escape (CVE-2026-64564, "SCTPhantom"); creating an SCTP socket
# needs no capability.
@test "socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP) ($mode)" {
	check_denied_protocol 'socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)'
}

# UDP-Lite has a NULL-ptr-deref via shared udp_mem accounting
# (CVE-2026-43164) and saw so little real-world use it's being removed from
# upstream entirely; creating a UDP-Lite socket needs no capability.
@test "socket(AF_INET, SOCK_DGRAM, IPPROTO_UDPLITE) ($mode)" {
	check_denied_protocol 'socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDPLITE)'
}

# MPTCP subflow/address cleanup had a double-free (CVE-2026-46170) and a
# remote DSS-option corruption bug (CVE-2026-80586, CVSS 9.8); creating an
# MPTCP socket needs no capability.
@test "socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP) ($mode)" {
	check_denied_protocol 'socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_MPTCP)'
}

# Ordinary AF_INET sockets are unaffected (family not blacklisted).
@test "socket(AF_INET, SOCK_STREAM) is unaffected ($mode)" {
	err=$(socket_py 'socket.socket(socket.AF_INET, socket.SOCK_STREAM)') && rc=0 || rc=$?
	check_allowed "$rc" "$err"
}
