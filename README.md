# bpf-lsm-progs
BPF LSM programs for Linux security policy enforcement

### Programs

| Program | LSM hooks | Description |
|---------|---------|-----------------|
| `userns_restrict` | `userns_create` | Blocks unprivileged user namespace creation. Processes without `CAP_SYS_ADMIN` (or already inside a nested namespace) cannot call `unshare(CLONE_NEWUSER)` or `clone(CLONE_NEWUSER)`. |
| `setuid_restrict` | `path_chmod`, `inode_create`, `path_mknod` | Prevents non-root processes from creating or setting the setuid bit, or the setgid bit on non-directories, via `chmod(2)`, `open(2)`, or `mknod(2)`. Setgid on a directory (group-inherit for new entries) is exempt. |

### Requirements

- Linux kernel with `CONFIG_BPF_LSM=y` & `CONFIG_DEBUG_INFO_BTF=y` enabled.
- `bpf` in `lsm` parameter in kernel cmdline.

### Build requirements

- bpftool
- clang
- libbpf-devel (libbpf-dev on Alpine & Debian based systems, bpf in Arch)
- llvm
- make

### Test requirements

- bats
- busybox
- util-linux

### Build

```sh
make
```

### Cross-compiling

```sh
make BPFTARGET=bpfeb
```

`make` detects the build host's byte order and uses that by default, so
this is only needed to build for a big-endian target (s390x) from a
little-endian machine, or vice versa.

Tested on SLES 16.0 (s390x).

### Load

```sh
make load
```

The restriction persists until unloaded or the system reboots.

### Unload

```sh
make unload
```

### Boot-time loading

```sh
sudo make install
```

Builds the programs, installs them under `/opt/bpf-lsm-progs` (override
with `TARGET=`), detects your initramfs generator (dracut, mkinitcpio, or
initramfs-tools), installs the matching hook, and regenerates the
initramfs so the programs load automatically on every boot, before the
real init system starts.

Tested on CachyOS (Arch, mkinitcpio), Debian 13 (initramfs-tools), and
Fedora (dracut). Alpine's `mkinitfs` has no hook mechanism for this
([mkinitfs#18](https://gitlab.alpinelinux.org/alpine/mkinitfs/-/issues/18)
is still open), so it isn't supported.

Undo with:

```sh
sudo make uninstall
```

Removes the deployed objects and the installed hook, then regenerates
the initramfs.

### Logging

Every denied attempt is logged via `bpf_printk` with the process's pid
and command name (plus context specific to the program, e.g. the uid).
This goes to the kernel's trace pipe, which nothing reads by default —
install the `bpf-tracepipe` service to forward it to your log. It's a
general-purpose forwarder, not specific to these programs, so it'll
also carry `bpf_printk` output from anything else on the system using
the trace pipe. To disable the logging entirely instead, build with
`make LOGGING=0`.

```sh
sudo make -C init install
```

Detects your init system ([Dinit](https://github.com/davmac314/dinit),
[OpenRC](https://wiki.gentoo.org/wiki/OpenRC),
[Runit](https://smarden.org/runit/),
[Systemd](https://systemd.io),
[SysVinit](https://wiki.gentoo.org/wiki/Sysvinit))
and installs the matching service. On systemd, view logs with
`journalctl -t bpf -f`; the rest go to syslog via `logger -t bpf`.
Undo with `sudo make -C init uninstall`.

Alternative init systems tested on Artix Linux (Arch, btw).
[S6](https://skarnet.org/software/s6-linux-init/)
was excluded due to its complexity.

### Test

```sh
make test
```

Runs the test suite for the current program, checking both its loaded
and unloaded behavior.
