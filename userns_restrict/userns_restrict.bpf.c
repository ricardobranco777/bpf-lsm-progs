// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define CAP_SYS_ADMIN	21
#define EPERM	1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile bool enabled = true;

SEC("lsm/userns_create")
int BPF_PROG(restrict_userns_create, struct cred *cred, int ret)
{
	if (ret != 0)
		return ret;
	if (!enabled)
		return 0;
	if (BPF_CORE_READ(cred, user_ns, level) != 0)
		return -EPERM;

	kernel_cap_t cap_eff = BPF_CORE_READ(cred, cap_effective);
	return (cap_eff.val & (1ULL << CAP_SYS_ADMIN)) ? 0 : -EPERM;
}
