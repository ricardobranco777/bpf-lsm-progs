// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.bpf.h"

#define CAP_SYS_ADMIN	21
#define EPERM	1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline void log_deny(uid_t uid, gid_t gid, bool nested,
				      bool privileged)
{
#if LOGGING
	struct task_struct *task = bpf_get_current_task_btf();
	pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);
	char comm[16], pcomm[16];

	bpf_get_current_comm(&comm, sizeof(comm));
	BPF_CORE_READ_STR_INTO(&pcomm, task, real_parent, comm);
	sanitize_comm(comm, sizeof(comm));
	sanitize_comm(pcomm, sizeof(pcomm));

	/* Keep comm & pcomm last so they can't spoof previous fields. */
	bpf_printk("userns_restrict: denied nested=%d privileged=%d "
		   "pid=%d uid=%d gid=%d ppid=%d cgroup=%llu pcomm=%s comm=%s",
		   nested, privileged, bpf_get_current_pid_tgid() >> 32,
		   uid, gid, ppid, bpf_get_current_cgroup_id(), pcomm, comm);
#endif
}

SEC("lsm/userns_create")
int BPF_PROG(restrict_userns_create, struct cred *cred, int ret)
{
	if (ret != 0)
		return ret;

	kernel_cap_t cap_eff = BPF_CORE_READ(cred, cap_effective);
	bool nested = BPF_CORE_READ(cred, user_ns, level) != 0;
	bool privileged = cap_eff.val & (1ULL << CAP_SYS_ADMIN);

	if (!nested && privileged)
		return 0;

	log_deny(BPF_CORE_READ(cred, uid.val), BPF_CORE_READ(cred, gid.val),
		 nested, privileged);
	return -EPERM;
}
