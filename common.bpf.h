// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef COMMON_BPF_H
#define COMMON_BPF_H

static __always_inline void log_denied(const char *prog, uid_t uid)
{
#if LOGGING
	char comm[16];
	unsigned int i;
	unsigned char c;

	bpf_get_current_comm(&comm, sizeof(comm));
	/*
	 * comm is attacker-controlled and could control characters and ANSI
	 * escapes. Blank out the C0 control range and DEL, not anything >=
	 * 0x80 so legitimate UTF-8 names survive. Comparing as unsigned char
	 * matters since plain (signed) char turns bytes above 0x80 negative.
	 * Keep it last in the format string so it can't spoof other fields.
	 */
	for (i = 0; i < sizeof(comm) - 1 && comm[i]; i++) {
		c = comm[i];
		if (c < 0x20 || c == 0x7f)
			comm[i] = '?';
	}
	bpf_printk("%s: denied pid=%d uid=%d comm=%s",
		   prog, bpf_get_current_pid_tgid() >> 32, uid, comm);
#endif
}

#endif
