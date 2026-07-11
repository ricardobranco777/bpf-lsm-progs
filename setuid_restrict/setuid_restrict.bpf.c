// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM	1
#define S_ISUID	0004000
#define S_ISGID	0002000

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

static __always_inline int deny_setuid_mode(umode_t mode, int ret)
{
	if (ret != 0)
		return ret;
	if (!policy_enabled())
		return 0;
	if (!(mode & (S_ISUID | S_ISGID)))
		return 0;

	struct task_struct *task = bpf_get_current_task_btf();
	uid_t uid = BPF_CORE_READ(task, cred, uid.val);
	if (uid == 0)
		return 0;

	return -EPERM;
}

/* chmod/fchmod/fchmodat: setuid/setgid on existing files */
SEC("lsm/path_chmod")
int BPF_PROG(setuid_restrict, const struct path *path, umode_t mode, int ret)
{
	return deny_setuid_mode(mode, ret);
}

/* open(O_CREAT)/creat: setuid/setgid in initial mode at creation */
SEC("lsm/inode_create")
int BPF_PROG(setuid_restrict_create, struct inode *dir, struct dentry *dentry,
	     umode_t mode, int ret)
{
	return deny_setuid_mode(mode, ret);
}

/* mknod: setuid/setgid on special files */
SEC("lsm/path_mknod")
int BPF_PROG(setuid_restrict_mknod, const struct path *dir,
	     struct dentry *dentry, umode_t mode, unsigned int dev, int ret)
{
	return deny_setuid_mode(mode, ret);
}
