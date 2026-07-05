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
- libbpf-devel (libbpf-dev on Debian based systems)
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

### Test

```sh
make test
```

Runs the [bats](https://github.com/bats-core/bats-core) suite in `tests/` against the current program — automatically detecting whether it's loaded (`/sys/fs/bpf/<program>`) and asserting the opposite behavior in each case (operation allowed when unloaded, blocked with `EPERM` when loaded).
