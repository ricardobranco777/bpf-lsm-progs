// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.bpf.h"

#define EAFNOSUPPORT	97

/*
 * Legacy/niche protocol families with a track record of locally-triggerable
 * memory-safety bugs and essentially no legitimate use on general-purpose
 * servers, desktops, or containers. None of these require a capability to
 * create, so any unprivileged process (including root inside a container's
 * user namespace) can reach the underlying code.
 */
#define AF_AX25		3	/* removed from mainline in 2026 (syzbot magnet); still shipped by most LTS/enterprise kernels */
#define AF_APPLETALK	5	/* removed from mainline in 2026 for the same reason as AX.25 */
#define AF_NETROM	6	/* amateur radio; removed alongside AX.25 */
#define AF_X25		9	/* legacy WAN protocol, essentially unused today */
#define AF_ROSE		11	/* amateur radio; CVE-2022-2318, CVE-2023-51782 (UAF); removed alongside AX.25 */
#define AF_RDS		21	/* CVE-2010-3904 (local root via unchecked userspace address) */
#define AF_IRDA		23	/* legacy infrared hardware, long unmaintained */
#define AF_CAN		29	/* CVE-2021-3609 (CAN BCM UAF, local root); legitimate on automotive/industrial gateways only */
#define AF_TIPC		30	/* CVE-2021-43267 (crypto heap overflow, local+remote) */
#define AF_ISDN		34	/* legacy telephony hardware, essentially unused today */
#define AF_PHONET	35	/* Nokia modem IPC, unused outside that hardware */
#define AF_IEEE802154	36	/* niche embedded wireless, uncommon outside embedded/IoT */
#define AF_CAIF		37	/* Ericsson modem IPC, unused outside that hardware */
#define AF_NFC		39	/* repeated UAF/OOB bugs in the LLCP layer */
#define AF_PPPOX	24	/* obscure legacy VPN (L2TP) and dial-up (PPPoE) protocols; blocks PPPoE too, not just L2TP */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline bool family_is_denied(int family)
{
	switch (family) {
	case AF_AX25:
	case AF_APPLETALK:
	case AF_NETROM:
	case AF_X25:
	case AF_ROSE:
	case AF_RDS:
	case AF_IRDA:
	case AF_CAN:
	case AF_TIPC:
	case AF_ISDN:
	case AF_PHONET:
	case AF_IEEE802154:
	case AF_CAIF:
	case AF_NFC:
	case AF_PPPOX:
		return true;
	default:
		return false;
	}
}

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

	if (!family_is_denied(family))
		return 0;

	__u64 uid_gid = bpf_get_current_uid_gid();
	log_denied("socket_create_restrict", (uid_t)uid_gid, (gid_t)(uid_gid >> 32));
	return -EAFNOSUPPORT;
}
