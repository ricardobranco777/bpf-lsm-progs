# setuid\_restrict

Prevents non-root processes from setting the setuid (`S_ISUID`) or setgid
(`S_ISGID`) bit on any file via `chmod(2)`.

A compromised service running as an unprivileged user could try to create a
setuid-root binary by copying `/bin/sh` to a writable directory and setting
the setuid bit.  This program blocks the `chmod` step, preventing that
privilege escalation path.

Note: root can still set setuid bits.  The `nosuid` mount option prevents
the *execution* of setuid binaries from a given filesystem regardless of
this program.

### Hook

`lsm/path_chmod` — fires on every `chmod(2)` and `fchmod(2)` call.  The
hook checks whether the requested mode includes `S_ISUID` or `S_ISGID` and
the caller's UID is non-zero.

### Alternatives

| Mechanism | Notes |
|---|---|
| [`nosuid` mount option](https://man7.org/linux/man-pages/man8/mount.8.html) | Prevents execution of setuid binaries from a specific filesystem; does not prevent the bits from being *set*. |
| [SELinux `setattr` permission](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/object_classes_permissions.md) | Can restrict `chmod` by domain; requires policy. |

No upstream sysctl prevents non-root users from setting the setuid bit.
