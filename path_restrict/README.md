# path\_restrict

Blocks `open(2)` of sensitive files for any process that does not hold
`CAP_SYS_ADMIN`.  Targets devices that the kernel does not gate on any
capability of their own:

| Path | Description |
|---|---|
| `/dev/fuse` | FUSE filesystem device |
| `/dev/kvm` | KVM hypervisor — VM creation |
| `/dev/vhost-*` | vhost-net, vhost-vsock (VM backends) |
| `/dev/vfio/*` | VFIO device passthrough |

These files are normally mode-restricted, but an LSM hook provides
defence-in-depth: the restriction holds even if permissions are changed or
another LSM grants access.

### Hook

`lsm/file_open` — fires on every `open(2)` call.  The hook resolves the
full path with `bpf_d_path` and compares it against the list of sensitive
device prefixes.  Can be toggled off without unloading via `make disable`
(see the top-level [README](../README.md#enable--disable)).

### Alternatives

| Mechanism | Notes |
|---|---|
| [File permissions / udev rules](https://man7.org/linux/man-pages/man7/udev.7.html) | Standard protection; can be bypassed by root or a process with `CAP_DAC_OVERRIDE`. |
| [SELinux](https://www.kernel.org/doc/html/latest/admin-guide/LSM/SELinux.html) / [AppArmor](https://www.kernel.org/doc/html/latest/admin-guide/LSM/apparmor.html) | Can restrict access by path or label with full policy. |
