# lockdown\_enforce

Enforces a subset of the kernel lockdown policy via BPF LSM, without
requiring `CONFIG_SECURITY_LOCKDOWN_LSM` or the `lockdown=` kernel
command-line parameter.

### Hook

`lsm/locked_down` — fires whenever kernel code calls
`security_locked_down(reason)`.  The hook checks the reason against the
denylist and returns `EPERM` for matching reasons.

### Alternatives

| Mechanism | Notes |
|---|---|
| [`lockdown=integrity` kernel parameter](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) | Enables the integrity lockdown level (blocks `KCORE`, `DEV_MEM`, etc.); requires `CONFIG_SECURITY_LOCKDOWN_LSM=y` and a reboot. |
| [`lockdown=confidentiality`](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) | Stricter lockdown level; also blocks tracefs, perf, etc. |

This program lets you enable lockdown-style policy on a running system with
a stock distribution kernel, without a reboot, and without permanently
enabling the lockdown LSM.  Individual reasons can be added or removed by
modifying the `switch` statement and reloading.

### Bugs / Limitations

- This program is experimental and for educational purposes only.  It offers no real protection because root can unload it.
The whole mechanism behind [kernel\_lockdown](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) resembles BSD's [secure_level](https://man.openbsd.org/securelevel), which is [not that great](https://isopenbsdsecu.re/mitigations/secure_levels/).
