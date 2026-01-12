# ProxyWatch

ProxyWatch is a Windows behavioral network inspection tool that identifies potential tunneling, proxying, and reverse-control patterns by correlating TCP tables and running processes. It operates without kernel drivers, ETW, or packet inspection — behavior is inferred purely from TCP state, process context, and heuristic scoring.

The tool can run continuously, score observed activity, classify roles (e.g., reverse-tunnel, proxy-listener), and optionally kill processes that exceed a configurable score threshold.

---

## Features
| Feature                   | Meaning |
|---------------------------|---------|
| `Behavior-based detection` | identifies proxy/tunnel patterns without signatures |
**Reverse-control detection** — persistent outbound channels are tracked temporally | 
**Reverse-transport classification** — detects payload forwarding over local TCP |
**Role assignment** — processes are labeled based on observed traffic patterns | 
**Outbound fan-out heuristics** — identifies multiplexing & multiple service targets  
**Client listener detection** — detects loopback/bound SOCKS-like behavior  
**Lateral movement hints** — flags internal connections to common lateral ports  
**Kill switch (optional)** — terminate high-scoring processes automatically  
**Run once or continuous** — suitable for terminal usage, scripting, or monitoring  
**No admin installation required** — uses standard Win32 APIs + `tasklist`  

---

## Roles

ProxyWatch assigns a best-fit role per process:

| Role                   | Meaning |
|------------------------|---------|
| `reverse-control`      | Persistent outbound control channel (idle) |
| `reverse-transport`    | Reverse-control + active local forwarding |
| `reverse-tunnel`       | Multiple outbound targets, no listener |
| `proxy-listener`       | Listener with clients + outbound forwarding |
| `listener-with-clients`| Local clients without outbound |
| `listener-with-outbound`| Listener, no clients, outbound activity |
| `listener-only`        | Listener without traffic |
| `outbound-only`        | Outbound activity only |
| `no-network-activity`  | Nothing interesting |

---

## How It Works (High-Level)

ProxyWatch uses:

- `GetExtendedTcpTable` (IPv4/IPv6) for TCP state & PID association
- `tasklist /V` for process info
- timestamped tracking of unique outbound connections for control-channel inference
- heuristic scoring + role classification

No packets are captured. No kernel components are required.  
All analysis is userland and stateful across scans.

---

## Installation

Clone & build:

```bash
git clone https://github.com/youruser/proxywatch.git
cd proxywatch
go build ./cmd/proxywatch

