// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.bpf.h"

#define EAFNOSUPPORT	97
#define EPROTONOSUPPORT	93

#define AF_INET		2
#define AF_INET6	10

/*
 * Legacy/niche protocol families with a track record of locally-triggerable
 * memory-safety bugs and essentially no legitimate use on general-purpose
 * servers, desktops, or containers. None of these require a capability to
 * create, so any unprivileged process (including root inside a container's
 * user namespace) can reach the underlying code.
 */
#define AF_ALG		38	/* CVE-2026-43043 (NULL deref), CVE-2026-43078 (page-reassignment overflow); userspace crypto libs use OpenSSL/etc, not the kernel crypto API */
#define AF_APPLETALK	5	/* removed from mainline in 2026 for the same reason as AX.25 */
#define AF_ATMPVC	8	/* CVE-2026-43050 (UAF), CVE-2026-72297 / CVE-2026-74689 (OOB); legacy ATM, essentially unused today */
#define AF_ATMSVC	20	/* same ATM stack as AF_ATMPVC, same CVE history */
#define AF_AX25		3	/* removed from mainline in 2026 (syzbot magnet); still shipped by most LTS/enterprise kernels */
#define AF_CAIF		37	/* Ericsson modem IPC, unused outside that hardware */
#define AF_CAN		29	/* CVE-2021-3609 (CAN BCM UAF, local root); legitimate on automotive/industrial gateways only */
#define AF_IEEE802154	36	/* niche embedded wireless, uncommon outside embedded/IoT */
#define AF_IRDA		23	/* legacy infrared hardware, long unmaintained */
#define AF_ISDN		34	/* legacy telephony hardware, essentially unused today */
#define AF_IUCV		32	/* CVE-2026-64004, CVE-2026-68140 (UAF), CVE-2026-68141, CVE-2026-68397; s390 z/VM guest IPC, unused outside mainframe hosts */
#define AF_KCM		41	/* CVE-2026-43244, CVE-2026-74262; kernel connection multiplexor, essentially no general-purpose use */
#define AF_KEY		15	/* legacy IPsec key management socket; superseded by netlink XFRM, essentially unused today */
#define AF_MCTP		45	/* niche BMC/management-controller IPC (I2C/I3C/USB/serial transports), unused outside that hardware */
#define AF_MPLS		28	/* MPLS routing is configured via rtnetlink; no legitimate reason to open this family as a plain socket */
#define AF_NETROM	6	/* amateur radio; removed alongside AX.25 */
#define AF_NFC		39	/* repeated UAF/OOB bugs in the LLCP layer */
#define AF_PHONET	35	/* Nokia modem IPC, unused outside that hardware */
#define AF_PPPOX	24	/* obscure legacy VPN (L2TP) and dial-up (PPPoE) protocols; blocks PPPoE too, not just L2TP */
#define AF_QIPCRTR	42	/* CVE-2026-46026, CVE-2026-43491 (QRTR name-service DoS); Qualcomm modem/DSP IPC, no general-purpose use */
#define AF_RDS		21	/* CVE-2010-3904 (local root via unchecked userspace address) */
#define AF_ROSE		11	/* amateur radio; CVE-2022-2318, CVE-2023-51782 (UAF); removed alongside AX.25 */
#define AF_RXRPC	33	/* CVE-2026-31635 "DirtyDecrypt" (RxGK page-cache corruption); legitimate only for kAFS (AFS filesystem) clients */
#define AF_SMC		43	/* IBM z Shared Memory Communications, unused outside mainframe hosts */
#define AF_TIPC		30	/* CVE-2021-43267 (crypto heap overflow, local+remote) */
#define AF_X25		9	/* legacy WAN protocol, essentially unused today */

/*
 * IP-layer protocols with a track record of local-root/DoS memory-safety
 * bugs and no legitimate use on general-purpose servers, desktops, or
 * containers. As with the address families above, creating any of these
 * needs no capability (they're SOCK_STREAM/SOCK_DGRAM/SOCK_SEQPACKET, not
 * SOCK_RAW), so any unprivileged process can reach them directly. Already
 * available as enum constants from vmlinux.h, so no #define needed here:
 *
 * IPPROTO_DCCP    - CVE-2017-6074 (double-free, public local-root exploit);
 *                   CVE-2020-16119 (dccp_disconnect() UAF). DCCP itself sees
 *                   essentially no real-world use.
 * IPPROTO_L2TP    - CVE-2016-10200 (l2tp_ip/l2tp_ip6 race UAF, local root).
 *                   This is the raw L2TPv3-over-IP encapsulation socket, not
 *                   the common L2TP/IPsec VPN path (which runs over UDP and
 *                   is unaffected).
 * IPPROTO_MPTCP   - CVE-2026-46170 (double-free in subflow/address
 *                   cleanup); CVE-2026-80586 (remote DSS corruption, CVSS
 *                   9.8). Actively-developed code still turning up bugs
 *                   under fuzzing.
 * IPPROTO_SCTP    - CVE-2026-64564 "SCTPhantom" (18-year-old ASCONF
 *                   use-after-free, local root + container escape).
 *                   Telecom signaling protocol, essentially no
 *                   general-purpose use.
 * IPPROTO_UDPLITE - CVE-2026-43164 (NULL-ptr-deref via shared udp_mem
 *                   accounting). Saw so little real-world adoption that
 *                   upstream is removing it entirely in Linux 7.1.
 */
static __always_inline bool protocol_is_denied(int family, int protocol)
{
	if (family != AF_INET && family != AF_INET6)
		return false;

	switch (protocol) {
	case IPPROTO_DCCP:
	case IPPROTO_L2TP:
	case IPPROTO_MPTCP:
	case IPPROTO_SCTP:
	case IPPROTO_UDPLITE:
		return true;
	default:
		return false;
	}
}

static __always_inline bool family_is_denied(int family)
{
	switch (family) {
	case AF_ALG:
	case AF_APPLETALK:
	case AF_ATMPVC:
	case AF_ATMSVC:
	case AF_AX25:
	case AF_CAIF:
	case AF_CAN:
	case AF_IEEE802154:
	case AF_IRDA:
	case AF_ISDN:
	case AF_IUCV:
	case AF_KCM:
	case AF_KEY:
	case AF_MCTP:
	case AF_MPLS:
	case AF_NETROM:
	case AF_NFC:
	case AF_PHONET:
	case AF_PPPOX:
	case AF_QIPCRTR:
	case AF_RDS:
	case AF_ROSE:
	case AF_RXRPC:
	case AF_SMC:
	case AF_TIPC:
	case AF_X25:
		return true;
	default:
		return false;
	}
}

static __always_inline void log_deny(int family, int type, int protocol)
{
#if LOGGING
	__u64 uid_gid = bpf_get_current_uid_gid();
	uid_t uid = uid_gid;
	gid_t gid = uid_gid >> 32;
	struct task_struct *task = bpf_get_current_task_btf();
	pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);
	char comm[16], pcomm[16];

	bpf_get_current_comm(&comm, sizeof(comm));
	BPF_CORE_READ_STR_INTO(&pcomm, task, real_parent, comm);
	sanitize_comm(comm, sizeof(comm));
	sanitize_comm(pcomm, sizeof(pcomm));

	/* Keep comm & pcomm last so they can't spoof previous fields. */
	bpf_printk("socket_create_restrict: denied family=%d type=%d protocol=%d "
		   "pid=%d uid=%d gid=%d ppid=%d cgroup=%llu pcomm=%s comm=%s",
		   family, type, protocol, bpf_get_current_pid_tgid() >> 32,
		   uid, gid, ppid, bpf_get_current_cgroup_id(), pcomm, comm);
#endif
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * kern=1 is kernel-internal socket creation (e.g. NFS/RPC transports), never
 * user-triggered; always allow it regardless of family.
 */
SEC("lsm/socket_create")
int BPF_PROG(socket_create_restrict, int family, int type, int protocol,
	     int kern, int ret)
{
	if (ret != 0 || kern)
		return ret;

	if (family_is_denied(family)) {
		log_deny(family, type, protocol);
		return -EAFNOSUPPORT;
	}

	if (protocol_is_denied(family, protocol)) {
		log_deny(family, type, protocol);
		return -EPROTONOSUPPORT;
	}

	return 0;
}
