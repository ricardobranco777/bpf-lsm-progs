// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef COMMON_BPF_H
#define COMMON_BPF_H

#if LOGGING
static __always_inline void sanitize_comm(char *comm, unsigned int len)
{
	unsigned int i;
	unsigned char c;

	/*
	 * comm is attacker-controlled and could contain control characters and
	 * ANSI escapes. Blank out the C0 control range and DEL, not anything
	 * >= 0x80, so legitimate UTF-8 names survive.  Comparing as unsigned
	 * char matters since plain signed char turns bytes above 0x80 negative.
	 */
	for (i = 0; i < len - 1 && comm[i]; i++) {
		c = comm[i];
		if (c < 0x20 || c == 0x7f)
			comm[i] = '?';
	}
}
#endif

static __always_inline void log_denied(const char *prog, uid_t uid, gid_t gid)
{
#if LOGGING
	char comm[16], pcomm[16];
	struct task_struct *task = bpf_get_current_task_btf();
	pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&comm, sizeof(comm));
	BPF_CORE_READ_STR_INTO(&pcomm, task, real_parent, comm);
	sanitize_comm(comm, sizeof(comm));
	sanitize_comm(pcomm, sizeof(pcomm));

	/* Keep comm & pcomm last so they can't spoof previous fields. */
	bpf_printk("%s: denied pid=%d uid=%d gid=%d ppid=%d cgroup=%llu pcomm=%s comm=%s",
		   prog, bpf_get_current_pid_tgid() >> 32, uid, gid, ppid,
		   bpf_get_current_cgroup_id(), pcomm, comm);
#endif
}

#endif
