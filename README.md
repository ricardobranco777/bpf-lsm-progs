# bpf-lsm-progs
BPF LSM programs for Linux security policy enforcement

### Programs

| Program | LSM hooks | Description |
|---------|---------|-----------------|
| `userns_restrict` | `userns_create` | Blocks unprivileged user namespace creation. Processes without `CAP_SYS_ADMIN` (or already inside a nested namespace) cannot call `unshare(CLONE_NEWUSER)` or `clone(CLONE_NEWUSER)`. |
| `setuid_restrict` | `path_chmod`, `inode_create`, `path_mknod` | Prevents non-root processes from creating or setting the setuid/setgid bit via `chmod(2)`, `open(2)`, or `mknod(2)`. |

### Requirements

- Linux kernel with `CONFIG_BPF_LSM=y` & `CONFIG_DEBUG_INFO_BTF=y` enabled.
- `bpf` in `lsm` parameter in kernel cmdline.

### Build requirements

- bpftool
- clang
- jq
- libbpf-devel (libbpf-dev on Debian based systems)
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

Builds for big-endian systems (s390x, ppc64 non-LE, sparc64, ...)
instead of the little-endian default, which covers x86_64, aarch64,
riscv64, and most other machines. No extra toolchain needed — just
copy the resulting `.o` file to the target. See the
[FAQ](FAQ.md#can-i-build-these-on-one-machine-and-run-them-on-another-architecture)
for more.

### Load

```sh
make load
```

The restriction persists until unloaded or the system reboots.

### Unload

```sh
make unload
```

### Enable / Disable

```sh
make disable
make enable
```

Temporarily turns a program's enforcement on or off without unloading
it. Takes effect immediately.

### Status

```sh
make status
```

Reports whether the program is not loaded, loaded and enabled/disabled,
and whether logging is on or off.

### Logging

```sh
make log-enable
make log-disable
```

When on, each denied attempt is logged via `bpf_printk` with the
process's pid and command name. Off by default. View with
`sudo cat /sys/kernel/tracing/trace_pipe` or `sudo bpftool prog tracelog`
while it's enabled — nothing is captured unless something is actively
reading the pipe at the time.

### Test

```sh
make test
```

Runs the test suite for the current program, checking both its loaded
and unloaded behavior.
