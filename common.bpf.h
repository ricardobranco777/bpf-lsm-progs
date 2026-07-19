// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef COMMON_BPF_H
#define COMMON_BPF_H

static __always_inline void log_denied(const char *prog, uid_t uid)
{
#if LOGGING
	char comm[16];

	bpf_get_current_comm(&comm, sizeof(comm));
	/* comm is attacker-controlled (prctl(PR_SET_NAME), argv[0]) and could
	 * contain text like "x uid=0" to spoof a naive log parser -- keep it
	 * last so it can't clobber a field that actually matters.
	 */
	bpf_printk("%s: denied pid=%d uid=%d comm=%s",
		   prog, bpf_get_current_pid_tgid() >> 32, uid, comm);
#endif
}

#endif
