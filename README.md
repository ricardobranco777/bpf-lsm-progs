# bpf-lsm-progs
BPF LSM programs for Linux security policy enforcement

### Programs

| Program | LSM hooks | Description |
|---------|---------|-----------------|
| `lockdown_enforce` | `locked_down` | Enforces kernel lockdown in a more granular way than `kernel_lockdown(7)`. |
| `path_restrict` | `file_open` | Blocks non-`CAP_SYS_ADMIN` processes from opening sensitive device files: `/dev/kvm`, `/dev/vhost-*`, `/dev/vfio/*`, etc. |
| `setuid_restrict` | `path_chmod`, `inode_create`, `path_mknod` | Prevents non-root processes from creating or setting the setuid/setgid bit via `chmod(2)`, `open(2)`, or `mknod(2)`. |
| `userns_restrict` | `userns_create` | Blocks unprivileged user namespace creation. Processes without `CAP_SYS_ADMIN` (or already inside a nested namespace) cannot call `unshare(CLONE_NEWUSER)` or `clone(CLONE_NEWUSER)`. |

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

Reports whether the program is not loaded, loaded and enabled, or
loaded and disabled.

### Test

```sh
make test
```

Runs the test suite for the current program, checking both its loaded
and unloaded behavior.
