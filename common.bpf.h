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

#endif
