**Why does rootless Podman still work after loading userns_restrict?**

Rootless Podman uses `catatonit -P` as a pause process to hold the user
namespace open. If the BPF program is loaded after Podman is already running,
the existing user namespace is unaffected. `userns_create` only fires on
creation, not on existing namespaces.

Killing the catatonit process tears down the user namespace. When Podman tries
to recreate it, `CLONE_NEWUSER` is blocked by the LSM and it gets `EPERM`.

See https://github.com/podman-container-tools/podman/issues/26578#issuecomment-3044062352
