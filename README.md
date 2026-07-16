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
- libbpf-devel (libbpf-dev on Alpine & Debian based systems)
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

### Test

```sh
make test
```

Runs the test suite for the current program, checking both its loaded
and unloaded behavior.
