# socket\_create\_restrict

Denies `socket(2)` creation for a fixed set of legacy/niche address
families that have repeatedly produced locally-triggerable memory-safety
bugs (use-after-free, heap overflow) and have essentially no legitimate
use on general-purpose servers, desktops, or containers:

`AF_AX25`, `AF_APPLETALK`, `AF_NETROM`, `AF_X25`, `AF_ROSE`, `AF_RDS`,
`AF_IRDA`, `AF_CAN`, `AF_TIPC`, `AF_ISDN`, `AF_PHONET`, `AF_IEEE802154`,
`AF_CAIF`, `AF_NFC`, `AF_PPPOX`, `AF_RXRPC`, `AF_QIPCRTR`.

None of these families require a capability to create a socket, so any
unprivileged process — including root inside a container's own user
namespace — can reach the underlying protocol code. That code is rarely
exercised in production and gets far less fuzzing/review than the core
`AF_INET`/`AF_UNIX` paths, which is why it keeps surfacing local-root and
DoS CVEs, e.g. [`CVE-2010-3904`](https://www.cve.org/CVERecord?id=CVE-2010-3904)
(RDS), [`CVE-2021-3609`](https://www.cve.org/CVERecord?id=CVE-2021-3609)
(CAN BCM UAF), [`CVE-2021-43267`](https://www.cve.org/CVERecord?id=CVE-2021-43267)
(TIPC crypto heap overflow), [`CVE-2022-2318`](https://www.cve.org/CVERecord?id=CVE-2022-2318) /
[`CVE-2023-51782`](https://www.cve.org/CVERecord?id=CVE-2023-51782) (ROSE UAF),
[`CVE-2026-31635`](https://www.cve.org/CVERecord?id=CVE-2026-31635) "DirtyDecrypt"
(RxGK page-cache corruption via `AF_RXRPC`),
[`CVE-2026-46026`](https://www.cve.org/CVERecord?id=CVE-2026-46026) /
[`CVE-2026-43491`](https://www.cve.org/CVERecord?id=CVE-2026-43491) (QRTR
name-service DoS). Unlike a privilege check, this policy applies to root
too — the whole point is to keep these code paths unreachable regardless
of who's asking.

In April 2026, upstream removed `AX.25`/`NET/ROM`/`ROSE` and `AppleTalk`
from mainline entirely, citing exactly this pattern (syzbot bug magnet,
no maintainer). Most deployed kernels are still on LTS/enterprise
branches that ship this code, so blocking it here still matters in
practice.

### Hook

`lsm/socket_create` — fires on every `socket(2)` call before the address
family is even looked up (and before any module autoload for it), so
denial doesn't depend on the corresponding kernel module being loaded or
even built. Kernel-internal socket creation (`kern=1`, e.g. NFS/RPC
transports) is always allowed.

### Bugs / Limitations

- The blacklist is a compile-time `switch` in
  `socket_create_restrict.bpf.c`, not runtime-configurable. If your
  workload has a legitimate need for one of these families (e.g. `AF_CAN`
  on an automotive/industrial gateway, `AF_NFC` for a smart-card reader,
  `AF_RXRPC` for kAFS/AFS filesystem clients, `AF_QIPCRTR` on a device
  with a Qualcomm modem/DSP), remove it from the list and rebuild.
- `AF_BLUETOOTH`, `AF_PACKET`, and `AF_NETLINK` are intentionally not
  included: they have real CVE history too, but also real, common
  legitimate use (Bluetooth stacks, DHCP clients, `NetworkManager`/
  `systemd-networkd`/`udev`), so blocking them needs to be scoped by
  caller rather than denied outright.
