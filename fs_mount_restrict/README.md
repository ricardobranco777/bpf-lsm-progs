# fs\_mount\_restrict

Denies `mount(2)` for a fixed set of legacy/niche filesystem types that
have repeatedly produced locally-triggerable memory-safety bugs and have
essentially no legitimate use on general-purpose servers, desktops, or
containers:

`adfs`, `affs`, `afs`, `befs`, `bfs`, `cramfs`, `efs`, `exofs`, `vxfs`
(`freevxfs`), `hfs`, `hfsplus`, `hpfs`, `jffs2`, `jfs`, `minix`, `nilfs2`,
`ntfs`, `ntfs3`, `omfs`, `orangefs`, `qnx4`, `qnx6`, `reiserfs`, `romfs`,
`sysv`, `ufs`, `zonefs`.

Mounting a filesystem on removable media needs no special privilege
beyond whatever an ordinary user-mount helper (`udisks`, `pmount`)
already grants for a USB stick or optical disc. These parsers are rarely
exercised in production and get far less fuzzing/review than
`ext4`/`xfs`/`btrfs`, which is why plugging in a malicious image is a
classic local attack vector -- and exactly why every major distro
blacklists these modules by default via `/etc/modprobe.d`.

### Hook

`lsm/sb_mount` -- fires on every `mount(2)` call with the filesystem type
string as given by the caller, before the type is resolved to a
registered `file_system_type` (and before any module autoload for it).
Denial doesn't depend on the corresponding module being loaded or even
built. `type` is `NULL` for bind mounts and remounts, which this program
ignores.

### Bugs / Limitations

- The blacklist is a fixed array in `fs_mount_restrict.bpf.c`, not
  runtime-configurable. If your workload has a legitimate need for one of
  these (e.g. `afs` for Kerberos-authenticated network filesystems,
  `ntfs`/`ntfs3` for Windows dual-boot drives), remove it from the list
  and rebuild.
- Only covers filesystem types passed directly to `mount(2)`. FUSE-based
  userspace implementations of some of these (e.g. `ntfs-3g`) mount as
  `fuse`/`fuseblk` and aren't affected either way.
- Modern, actively-maintained filesystems that happen to also appear on
  some distros' blacklists for unrelated reasons (e.g. `f2fs`) are
  intentionally not included here -- this list is limited to drivers with
  a genuine history of being obscure *and* buggy.
