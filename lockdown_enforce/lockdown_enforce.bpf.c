// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM	1

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/locked_down")
int BPF_PROG(lockdown_enforce, enum lockdown_reason what, int ret)
{
	if (ret != 0)
		return ret;
	/*
	 * Full list in lockdown_reasons array in:
	 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/security/security.c
	 */
	switch (what) {
	/*
	 * Blocked in lockdown=integrity & lockdown=confidentiality modes:
	 */
	case LOCKDOWN_MODULE_SIGNATURE:		// unsigned module loading
	case LOCKDOWN_DEV_MEM:			// /dev/mem,kmem,port
	case LOCKDOWN_EFI_TEST:			// /dev/efi_test access
	case LOCKDOWN_KEXEC:			// kexec of unsigned images
	case LOCKDOWN_HIBERNATION:		// hibernation
	case LOCKDOWN_PCI_ACCESS:		// direct PCI access
	case LOCKDOWN_IOPORT:			// raw io port access
	case LOCKDOWN_MSR:			// raw MSR access
	case LOCKDOWN_ACPI_TABLES:		// modifying ACPI tables
	case LOCKDOWN_DEVICE_TREE:		// modifying device tree contents
	case LOCKDOWN_PCMCIA_CIS:		// direct PCMCIA CIS storage
	case LOCKDOWN_TIOCSSERIAL:		// reconfiguration of serial port IO
	case LOCKDOWN_MODULE_PARAMETERS:	// unsafe module parameters
	case LOCKDOWN_MMIOTRACE:		// unsafe mmio
	case LOCKDOWN_DEBUGFS:			// debugfs access
	case LOCKDOWN_XMON_WR:			// xmon write access
#if 0	/* We want to load BPF programs */
	case LOCKDOWN_BPF_WRITE_USER:		// use of bpf to write user RAM
#endif
	case LOCKDOWN_DBG_WRITE_KERNEL:		// use of kgdb/kdb to write kernel RAM
	case LOCKDOWN_RTAS_ERROR_INJECTION:	// RTAS error injection
#ifdef	LOCKDOWN_XEN_USER_ACTIONS
	case LOCKDOWN_XEN_USER_ACTIONS:		// Xen guest user action
#endif
	/*
	 * Blocked in confidentiality mode only:
	 */
	case LOCKDOWN_KCORE:			// /proc/kcore access
	case LOCKDOWN_KPROBES:			// use of kprobes
#if 0	/* We want to load BPF programs */
	case LOCKDOWN_BPF_READ_KERNEL:		// use of bpf to read kernel RAM
#endif
	case LOCKDOWN_DBG_READ_KERNEL:		// use of kgdb/kdb to read kernel RAM
	case LOCKDOWN_PERF:			// unsafe use of perf
	case LOCKDOWN_TRACEFS:			// use of tracefs
	case LOCKDOWN_XMON_RW:			// xmon read and write access
	case LOCKDOWN_XFRM_SECRET:		// xfrm SA secret
		return -EPERM;
	default:
		return 0;
	}
}
