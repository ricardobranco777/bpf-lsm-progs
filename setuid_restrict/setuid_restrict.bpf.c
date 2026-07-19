// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.bpf.h"

#define EPERM	1
#define S_ISUID	0004000
#define S_ISGID	0002000

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline int deny_setuid_mode(umode_t mode, int ret)
{
	if (ret != 0)
		return ret;
	if (!(mode & (S_ISUID | S_ISGID)))
		return 0;

	__u64 uid_gid = bpf_get_current_uid_gid();
	uid_t uid = uid_gid;
	gid_t gid = uid_gid >> 32;
	if (uid == 0)
		return 0;

	log_denied("setuid_restrict", uid, gid);
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
