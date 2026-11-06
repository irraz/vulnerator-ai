---
name: l3-recon-pivot
description: Enumerate layer-3 network topology behind NAT, validate findings, and recognize when a target is unreachable from your position.
version: 0.1.0
author: vulnerator-ai
license: MIT
metadata:
  hermes:
    tags: [Security, Pentest, Network, Recon, L3]
    related_skills: [pentest-ooda]
    # Conditional activation: it only appears if the Kali MCP's ACTION tool is present,
    # just like pentest-ooda. If there is no network to enumerate, this knowledge does NOT clutter the prompt.
    requires_tools: [mcp_kali_kali_run]
---

# L3 recon and pivoting behind NAT

Domain knowledge for the network reconnaissance phase when the target is on a DIFFERENT subnet
than yours and there is NAT in between (e.g. you run inside a container). It complements `pentest-ooda`: it
does not change the loop's discipline, it brings the technique to enumerate layer 3 and, above all, to
distinguish "I am still discovering terrain" from "I already know I cannot get through".

## When to Use

When the target is NOT on your same subnet and you need to discover the topology (gateways, hops,
subnets) or decide whether the target is even reachable from your position. If the target is already
on your segment or you were given it by IP, you do NOT need this: go straight to scanning.

## Map your position before scanning anything

Before sweeping ranges, situate yourself. A couple of cheap reads tell you where you are and where there is
an exit:

- **Your subnet and your gateway**: `ip route` / `/proc/net/route`, `ip addr`. The `default via <gw>` is your
  only L3 exit; anything that is not your local subnet leaves through there.
- **Your L2 neighborhood**: `ip neigh` / `arp -a`. It ONLY sees your local broadcast domain. If the target
  is not here, ARP will never find it for you (it does not cross routers or NAT).
- **Resolution and internet egress**: `/etc/resolv.conf` (the DNS served to you), `curl -s ifconfig.me`
  or `cloudflare.com/cdn-cgi/trace` (your effective public IP). Useful to understand where you egress, NOT
  to find a target on someone else's LAN.

With this you already know: how many NAT hops you have in front of you and whether the target falls inside or outside your
L3 reach.

## Understand NAT in layers (the container case)

If you run inside a container, you will normally have SEVERAL layers of NAT between you and a "real" LAN:

```
container (you)  ->  container-network gateway  ->  [host / VM]  ->  real router  ->  internet
```

Every arrow that crosses a NAT is a boundary you CANNOT traverse at the L2/L3 level with scanning alone:
the NAT rewrites addresses and does not forward your arbitrary traffic toward the subnet behind it. Recognizing
which layer you are in is what tells you whether a target is reachable or not. A `traceroute` to an internet
destination shows you your first hops; if the second hop already does not respond (`* * *`), you have a
NAT/filter in front and the subnet beyond is NOT within your direct reach.

## Validate findings before building on them

A discovery finding is NOT a fact until you confirm it with a second independent signal.
Firewalls and NAT produce FALSE POSITIVES that wreck the OODA loop if you treat them as real:

- `nmap -sn <range>` that reports "N active hosts" may be the firewall answering for the whole
  subnet. **Confirm** with a real `ping` or a port that actually responds before calling a host
  alive. "Host up" with no corroborating packet = suspicious.
- An "open|filtered" port (UDP, or TCP behind a firewall) is NOT a confirmed open port.
- If an entire subnet appears "full of hosts" all at once, be suspicious: it is the typical pattern of a
  device that ACKs everything. Verify one before scanning them all.

Rule: do not base the next step on a finding you have not corroborated. A false positive
chased is a wasted OODA cycle.

## Pivoting when there is an intermediary

If you discover a service that can forward traffic for you (an HTTP proxy such as Squid, a dual-homed
host, a reachable SSH), that is the LEGITIMATE path to get further when direct scanning
does not cross. Test it in a bounded way before assuming anything: e.g. `curl -x http://<proxy>:<port>
<test-url>` to see if the proxy takes you out to another network, or just echoes your same egress. A proxy
that returns YOUR SAME public IP is not pivoting you anywhere new.

## Recognize unreachability (the STOP criterion)

This is the part that matters most, because it is where the loop derails. If after a few DIFFERENT
tactics (map the route, ARP, traceroute, a pivot attempt) you confirm that:

- the target is behind one or more NATs you cannot cross, and
- you have no intermediary that forwards toward its subnet,

then the target is **unreachable from your position**. That is NOT a progress step even if each
attempt gave you new egress: you have learned about terrain that does not contain the answer. STOP,
consolidate the topology you DID discover, and HAND control back to the operator explaining why it is
unreachable and what you would need (be given the IP, another network position, a valid pivot). Do not keep
sweeping subnets at random: more attempts will not open a route that physically does not exist.

## Pitfalls

- **Confusing "I discovered something new" with "advance toward the target".** Mapping the Nth subnet of the
  container infra does not get you closer to a router on someone else's LAN.
- **Chasing firewall/NAT false positives** without confirming them with a second signal.
- **Repeating the same tactic** expecting a different result (another traceroute, another sweep of the same
  range): if a path already proved not to cross, repeating it is not progress.
- **Sweeping private ranges at random** (192.168.x, 10.x) "just in case": without an L3 route to them, they
  do not leave your NAT.

## Verification

Before considering the L3 recon phase done, confirm: (a) you situated your position (subnet, gateway,
NAT layers) before sweeping; (b) every host/port you call alive is corroborated by a second
signal, not by a single `nmap -sn`; (c) if the target turned out to be unreachable, you STOPPED and reported it instead
of continuing to discover irrelevant terrain.
