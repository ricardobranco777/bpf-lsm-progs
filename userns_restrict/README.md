# userns\_restrict

Restricts unprivileged user namespace creation.  Processes without
`CAP_SYS_ADMIN` may not call `unshare(CLONE_NEWUSER)` or `clone(CLONE_NEWUSER)`.
Nested user namespaces are always denied regardless of capabilities.

Functionally equivalent to the Debian
`kernel.unprivileged_userns_clone=0` sysctl
[patch](https://github.com/semplice/linux/blob/master/debian/patches/debian/add-sysctl-to-disallow-unprivileged-CLONE_NEWUSER-by-default.patch),
without modifying the kernel.

### Hook

`lsm/userns_create` — fires on every `unshare(CLONE_NEWUSER)` and
`clone(CLONE_NEWUSER)` call.  The hook denies if the caller's user namespace
level is non-zero (nested namespace) or the caller lacks `CAP_SYS_ADMIN`.

### Alternatives

| Mechanism | Notes |
|---|---|
| [`kernel.unprivileged_userns_clone=0`](https://wiki.debian.org/LXC#Enable_Unprivileged_User_Namespaces) | Debian/Ubuntu kernel patch; not available in upstream kernels. |
| [`user.max_user_namespaces=0`](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/user.html) | Upstream sysctl; also blocks root, making it too broad for most deployments. |
| [SELinux `user_namespace { create }`](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/object_classes_permissions.md) | Can restrict namespace creation by domain; requires policy. |
| [AppArmor `userns` restriction](https://gitlab.com/apparmor/apparmor/-/wikis/unprivileged_userns_restriction) | Available since AppArmor 4.0 / kernel 6.7; restricts by profile. |

### Bugs / Limitations

- Breaks rootless containers for obvious reasons.
- See the [FAQ](../FAQ.md#does-userns_restrict-break-browser-sandboxing-firefox-chromium-thunderbird)
  for specifics on each application's fallback behavior (or lack thereof).
- Also affects Flatpak apps unless `bwrap` is installed setuid-root — see the
  [FAQ](../FAQ.md#does-userns_restrict-break-flatpak-apps).
