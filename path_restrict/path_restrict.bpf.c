// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define CAP_SYS_ADMIN	21
#define EPERM		1

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#define PREFIX_MAX	16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static const struct {
	char prefix[PREFIX_MAX];
	bool exact;	/* if true, full path must match */
} sensitive[] = {
	{ "/dev/kvm",    true },  /* KVM hypervisor */
	{ "/dev/fuse",   true },  /* FUSE filesystem */
	{ "/dev/vfio",   false }, /* VFIO passthrough */
	{ "/dev/vhost-", false }, /* vhost-net/vsock */
};

/*
 * Compares the NUL-terminated pfx (max PREFIX_MAX bytes) against s.
 * Returns the matched length on success, or -1 on mismatch.
 */
static __always_inline int prefix_match(const char *pfx, const char *s)
{
#pragma unroll
	for (int i = 0; i < PREFIX_MAX; i++) {
		if (pfx[i] == '\0')
			return i;
		if (pfx[i] != s[i])
			return -1;
	}
	return PREFIX_MAX;
}

SEC("lsm/file_open")
int BPF_PROG(sensitive_files, struct file *file, int ret)
{
	if (ret != 0)
		return ret;

	char path[64];
	int n = bpf_d_path((struct path *)&file->f_path, path, sizeof(path));
	if (n <= 0)
		return 0;

	bool matched = false;
#pragma unroll
	for (unsigned int i = 0; i < ARRAY_SIZE(sensitive); i++) {
		int len = prefix_match(sensitive[i].prefix, path);
		if (len < 0)
			continue;
		if (sensitive[i].exact && n != len + 1)
			continue;
		matched = true;
		break;
	}

	if (!matched)
		return 0;

	struct task_struct *task = bpf_get_current_task_btf();
	kernel_cap_t cap_eff = BPF_CORE_READ(task, cred, cap_effective);
	if (cap_eff.val & (1ULL << CAP_SYS_ADMIN))
		return 0;

	return -EPERM;
}
