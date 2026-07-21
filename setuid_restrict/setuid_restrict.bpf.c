// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.bpf.h"

#define EPERM	1
#define S_ISUID	0004000
#define S_ISGID	0002000
#define S_IFMT	0170000
#define S_IFDIR	0040000

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline int deny_setuid_mode(umode_t mode, bool is_dir, int ret)
{
	if (ret != 0)
		return ret;

	umode_t forbidden = is_dir ? S_ISUID : (S_ISUID | S_ISGID);
	if (!(mode & forbidden))
		return 0;

	__u64 uid_gid = bpf_get_current_uid_gid();
	uid_t uid = uid_gid;
	gid_t gid = uid_gid >> 32;
	if (uid == 0)
		return 0;

	log_denied("setuid_restrict", uid, gid);
	return -EPERM;
}

/*
 * chmod/fchmod/fchmodat: setuid/setgid on existing files. setgid on a
 * directory only makes new entries inherit its group -- no privilege
 * escalation risk, so only setuid is restricted there.
 */
SEC("lsm/path_chmod")
int BPF_PROG(setuid_restrict, const struct path *path, umode_t mode, int ret)
{
	umode_t imode = BPF_CORE_READ(path, dentry, d_inode, i_mode);

	return deny_setuid_mode(mode, (imode & S_IFMT) == S_IFDIR, ret);
}

/*
 * open(O_CREAT)/creat: setuid/setgid in initial mode at creation. Always a
 * regular file -- vfs_create() never creates a directory.
 */
SEC("lsm/inode_create")
int BPF_PROG(setuid_restrict_create, struct inode *dir, struct dentry *dentry,
	     umode_t mode, int ret)
{
	return deny_setuid_mode(mode, false, ret);
}

/*
 * mknod: setuid/setgid on special files. Never a directory -- mknod(2)
 * rejects S_IFDIR.
 */
SEC("lsm/path_mknod")
int BPF_PROG(setuid_restrict_mknod, const struct path *dir,
	     struct dentry *dentry, umode_t mode, unsigned int dev, int ret)
{
	return deny_setuid_mode(mode, false, ret);
}
