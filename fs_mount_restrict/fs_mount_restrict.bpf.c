// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.bpf.h"

#define ENODEV		19
#define FSTYPE_LEN	16

/*
 * Legacy/niche filesystem drivers with a track record of locally-triggerable
 * memory-safety bugs and essentially no legitimate use on general-purpose
 * servers, desktops, or containers. mount(2) on removable media (e.g. via
 * udisks) needs no capability beyond ordinary user-mount permissions, so
 * these rarely-fuzzed parsers are a classic vector for malicious USB/optical
 * media -- this is why every major distro blacklists them by default.
 */
static const char *const denied_fstypes[] = {
	"adfs", "affs", "afs", "befs", "bfs", "cramfs", "efs", "exofs",
	"vxfs", "hfs", "hfsplus", "hpfs", "jffs2", "jfs", "minix",
	"nilfs2", "ntfs", "ntfs3", "omfs", "orangefs", "qnx4", "qnx6",
	"reiserfs", "romfs", "sysv", "ufs", "zonefs",
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline bool fstype_is_denied(const char *buf)
{
#pragma unroll
	for (unsigned int i = 0; i < (sizeof(denied_fstypes) / sizeof(denied_fstypes[0])); i++) {
		if (bpf_strncmp(buf, FSTYPE_LEN, denied_fstypes[i]) == 0)
			return true;
	}
	return false;
}

static __always_inline void log_deny(const char *fstype)
{
#if LOGGING
	__u64 uid_gid = bpf_get_current_uid_gid();
	uid_t uid = uid_gid;
	gid_t gid = uid_gid >> 32;
	struct task_struct *task = bpf_get_current_task_btf();
	pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);
	char comm[16], pcomm[16];

	bpf_get_current_comm(&comm, sizeof(comm));
	BPF_CORE_READ_STR_INTO(&pcomm, task, real_parent, comm);
	sanitize_comm(comm, sizeof(comm));
	sanitize_comm(pcomm, sizeof(pcomm));

	/* Keep comm & pcomm last so they can't spoof previous fields. */
	bpf_printk("fs_mount_restrict: denied fstype=%s "
		   "pid=%d uid=%d gid=%d ppid=%d cgroup=%llu pcomm=%s comm=%s",
		   fstype, bpf_get_current_pid_tgid() >> 32,
		   uid, gid, ppid, bpf_get_current_cgroup_id(), pcomm, comm);
#endif
}

/*
 * type is NULL for bind mounts and remounts (no filesystem type given) --
 * nothing to check there.
 */
SEC("lsm/sb_mount")
int BPF_PROG(fs_mount_restrict, const char *dev_name, struct path *path,
	     const char *type, unsigned long flags, void *data, int ret)
{
	if (ret != 0 || !type)
		return ret;

	char buf[FSTYPE_LEN] = {};
	if (bpf_probe_read_kernel_str(buf, sizeof(buf), type) < 0)
		return 0;

	if (!fstype_is_denied(buf))
		return 0;

	log_deny(buf);
	return -ENODEV;
}
