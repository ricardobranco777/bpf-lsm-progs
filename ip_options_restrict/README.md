# ip\_options\_restrict

Drops incoming IPv4 TCP connection requests (SYNs, or the final ACK when
syncookies are in use) that carry IP options (LSRR, SSRR, RR, TS, ...).
This is the Linux counterpart of FreeBSD's `net.inet.ip.process_options=2`
for TCP.

It blocks the trigger for CVE-2026-98432, a race in `tcp_v4_syn_recv_sock()`
where `ireq->ireq_opt` is passed to the child socket without being copied.
Legitimate TCP traffic virtually never uses IP options, so nothing should
break.

Hook: `lsm/inet_conn_request`. It does not cover UDP, ICMP or established
TCP connections, and it is not a substitute for installing a fixed kernel.

## Alternatives

If you don't need a BPF LSM program for this, a firewall rule does the same
job. A packet has IP options when its header is longer than 20 bytes (IHL > 5).

nftables:

```
nft add table inet filter
nft add chain inet filter prerouting '{ type filter hook prerouting priority raw; policy accept; }'
nft add rule inet filter prerouting 'ip hdrlength > 20 counter drop'
```

To only drop TCP SYNs with options (what this program does), use
`tcp flags & (syn|ack) == syn ip hdrlength > 20` instead.

iptables:

```
iptables -t raw -A PREROUTING -m u32 --u32 "0>>24&0xF=6:15" -j DROP
```

Source routing (LSRR/SSRR) can also be turned off with a sysctl:

```
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
```

Differences from this program:

- The rules above also drop options on non-TCP traffic, including Router
  Alert (IGMP), so multicast can stop working. Exempt it with
  `ip protocol igmp accept` if you need it.
- They are firewall state that other tools (firewalld, ufw, container
  runtimes) can flush or reorder. A BPF LSM program is loaded once at boot
  and can't be removed without `CAP_BPF`/`CAP_SYS_ADMIN`.
- FreeBSD's `net.inet.ip.process_options=2` replies with ICMP
  "administratively prohibited"; use `reject with icmp type admin-prohibited`
  in nftables if you want that. This program drops silently.
