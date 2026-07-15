// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#ifndef COMMON_BPF_H
#define COMMON_BPF_H

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} enabled SEC(".maps");

static __always_inline bool policy_enabled(void)
{
	__u32 key = 0;
	__u8 *val = bpf_map_lookup_elem(&enabled, &key);

	return val && *val;
}

#endif
