# socket\_create\_restrict

Denies `socket(2)` creation for a fixed set of legacy/niche address
families and IP-layer protocols that have repeatedly produced
locally-triggerable memory-safety bugs (use-after-free, heap overflow)
and have essentially no legitimate use on general-purpose servers,
desktops, or containers:

Address families: `AF_AX25`, `AF_APPLETALK`, `AF_NETROM`, `AF_X25`,
`AF_ROSE`, `AF_RDS`, `AF_IRDA`, `AF_CAN`, `AF_TIPC`, `AF_ISDN`,
`AF_PHONET`, `AF_IEEE802154`, `AF_CAIF`, `AF_NFC`, `AF_PPPOX`,
`AF_RXRPC`, `AF_QIPCRTR`.

Protocols (within `AF_INET`/`AF_INET6`): `IPPROTO_DCCP`, `IPPROTO_L2TP`,
`IPPROTO_SCTP`, `IPPROTO_UDPLITE`, `IPPROTO_MPTCP`.

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

A second, narrower blacklist targets specific IP-layer *protocols*
within the always-allowed `AF_INET`/`AF_INET6` families, for the same
reason: `IPPROTO_DCCP`, `IPPROTO_L2TP`, `IPPROTO_SCTP`, `IPPROTO_UDPLITE`,
`IPPROTO_MPTCP`. None of these require a capability to create either —
plain `SOCK_STREAM`/`SOCK_DGRAM`/`SOCK_SEQPACKET`, not `SOCK_RAW` — and
each has a track record to match:
[`CVE-2017-6074`](https://www.cve.org/CVERecord?id=CVE-2017-6074) /
[`CVE-2020-16119`](https://www.cve.org/CVERecord?id=CVE-2020-16119) (DCCP
double-free and `dccp_disconnect()` use-after-free, both with public
local-root exploits),
[`CVE-2016-10200`](https://www.cve.org/CVERecord?id=CVE-2016-10200) (L2TP
IP-encapsulation race UAF, local root),
[`CVE-2026-64564`](https://www.cve.org/CVERecord?id=CVE-2026-64564)
"SCTPhantom" (18-year-old SCTP ASCONF use-after-free, local root +
container escape),
[`CVE-2026-43164`](https://www.cve.org/CVERecord?id=CVE-2026-43164)
(UDP-Lite NULL-pointer dereference via shared `udp_mem` accounting), and
[`CVE-2026-46170`](https://www.cve.org/CVERecord?id=CVE-2026-46170) /
[`CVE-2026-80586`](https://www.cve.org/CVERecord?id=CVE-2026-80586) (MPTCP
subflow-cleanup double-free and a remote DSS-option corruption bug, CVSS
9.8). DCCP and UDP-Lite in particular see essentially no real-world
deployment — UDP-Lite is being removed from upstream entirely in Linux
7.1 for exactly that reason (unused code, syzbot the only thing that ever
found its bugs).

### Hook

`lsm/socket_create` — fires on every `socket(2)` call before the address
family is even looked up (and before any module autoload for it), so
denial doesn't depend on the corresponding kernel module being loaded or
even built. Kernel-internal socket creation (`kern=1`, e.g. NFS/RPC
transports) is always allowed.

### Bugs / Limitations

- Both blacklists are compile-time `switch` statements in
  `socket_create_restrict.bpf.c`, not runtime-configurable. If your
  workload has a legitimate need for one of these families (e.g. `AF_CAN`
  on an automotive/industrial gateway, `AF_NFC` for a smart-card reader,
  `AF_RXRPC` for kAFS/AFS filesystem clients, `AF_QIPCRTR` on a device
  with a Qualcomm modem/DSP) or protocols (e.g. `IPPROTO_SCTP` for
  telecom signaling, `IPPROTO_L2TP` for L2TPv3 pseudowires, `IPPROTO_MPTCP`
  for multipath-aware clients), remove it from the relevant list and
  rebuild.
- `AF_BLUETOOTH`, `AF_PACKET`, and `AF_NETLINK` are intentionally not
  included: they have real CVE history too, but also real, common
  legitimate use (Bluetooth stacks, DHCP clients, `NetworkManager`/
  `systemd-networkd`/`udev`), so blocking them needs to be scoped by
  caller rather than denied outright.
- The protocol blacklist only catches sockets that *explicitly* request
  one of these `IPPROTO_*` values. It doesn't stop MPTCP negotiated
  transparently on top of an ordinary `IPPROTO_TCP` socket via the
  `net.mptcp.enabled` sysctl — that path never presents `IPPROTO_MPTCP`
  to this hook.
