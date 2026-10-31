// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.bpf.h"

#define EPERM		1
#define AF_INET		2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Drops incoming IPv4 TCP connection requests (SYNs, or the final ACK when
 * syncookies are in use) that carry IP options (LSRR, SSRR, RR, TS, etc.).
 *
 * This is the Linux counterpart of FreeBSD's net.inet.ip.process_options=2.
 * It also blocks the trigger for CVE-2026-98432, a race in
 * tcp_v4_syn_recv_sock() where ireq->ireq_opt is handed to the child socket
 * without being copied.  The request sock only gets ireq_opt set when the
 * SYN had options, so a NULL check is enough and legitimate traffic (which
 * virtually never uses IP options) is unaffected.
 *
 * It runs in softirq context, so there is no current task to log.
 */
SEC("lsm/inet_conn_request")
int BPF_PROG(ip_options_restrict, const struct sock *sk, struct sk_buff *skb,
	     struct request_sock *req, int ret)
{
	struct inet_request_sock *ireq = (struct inet_request_sock *)req;
	struct ip_options_rcu *opt;

	if (ret != 0)
		return ret;

	/* ireq_opt shares a union with the IPv6 fields */
	if (BPF_CORE_READ(req, __req_common.skc_family) != AF_INET)
		return 0;

	opt = BPF_CORE_READ(ireq, ireq_opt);
	if (!opt)
		return 0;

#if LOGGING
	{
		__be32 saddr = BPF_CORE_READ(req, __req_common.skc_daddr);
		__u16 sport = __builtin_bswap16(BPF_CORE_READ(req, __req_common.skc_dport));
		__u16 dport = BPF_CORE_READ(req, __req_common.skc_num);

		bpf_printk("ip_options_restrict: denied TCP SYN with IP options "
			   "optlen=%u saddr=%pI4 sport=%u dport=%u",
			   BPF_CORE_READ(opt, opt.optlen), &saddr, sport, dport);
	}
#endif
	return -EPERM;
}
