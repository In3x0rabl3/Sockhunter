//go:build windows
// +build windows

package candidate

import (
	"net"

	"proxywatch/internal/netstat"
	"proxywatch/internal/process"
)

type Candidate struct {
	Proc           *process.ProcessInfo
	Listeners      []netstat.ListenerInfo
	Conns          []netstat.ConnectionInfo
	Score          int
	Reasons        []string
	ActiveProxying bool
	Role           string

	ControlChannel         *netstat.ConnectionInfo
	ControlDurationSeconds int

	OutTotal    int
	OutExternal int
	OutInternal int
}

var internalCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

var lateralPorts = map[int]bool{
	445:  true,
	3389: true,
	5985: true,
	5986: true,
	139:  true,
	389:  true,
	636:  true,
	1433: true,
	22:   true,
}

func IsInternalIP(ip string) bool {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return false
	}
	for _, cidr := range internalCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(netIP) {
			return true
		}
	}
	return false
}

func IsLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

func IsWildcardIP(ip string) bool {
	return ip == "0.0.0.0" || ip == "::"
}

func TrimName(name string, max int) string {
	if len(name) <= max {
		return name
	}
	if max <= 3 {
		return name[:max]
	}
	return name[:max-3] + "..."
}

func SocksListenerPorts(listeners []netstat.ListenerInfo) (ports map[int]struct{}, loopbackOnly bool, anyWildcard bool) {
	ports = make(map[int]struct{})
	loopbackOnly = true
	anyWildcard = false

	for _, l := range listeners {
		ports[l.LocalPort] = struct{}{}

		if IsWildcardIP(l.LocalAddress) {
			anyWildcard = true
			loopbackOnly = false
		} else if !IsLoopbackIP(l.LocalAddress) {
			loopbackOnly = false
		}
	}
	return ports, loopbackOnly, anyWildcard
}

func CountActiveClientSessions(conns []netstat.ConnectionInfo, listenPorts map[int]struct{}) (clients int, clientRemoteIPs map[string]int) {
	clientRemoteIPs = make(map[string]int)
	for _, c := range conns {
		if c.State != "ESTABLISHED" {
			continue
		}
		if _, ok := listenPorts[c.LocalPort]; !ok {
			continue
		}
		if c.RemotePort <= 0 {
			continue
		}
		if c.RemoteAddress == "" || IsWildcardIP(c.RemoteAddress) {
			continue
		}
		clients++
		clientRemoteIPs[c.RemoteAddress]++
	}
	return clients, clientRemoteIPs
}

func OutboundTargets(conns []netstat.ConnectionInfo, listenPorts map[int]struct{}) (outTotal int, outExternal int, outInternal int) {
	for _, c := range conns {
		if c.State != "ESTABLISHED" {
			continue
		}
		if c.RemoteAddress == "" || IsWildcardIP(c.RemoteAddress) || IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := listenPorts[c.LocalPort]; ok {
			continue
		}

		outTotal++
		if IsInternalIP(c.RemoteAddress) {
			outInternal++
		} else {
			outExternal++
		}
	}
	return outTotal, outExternal, outInternal
}

func HasInternalLateral(conns []netstat.ConnectionInfo) bool {
	for _, c := range conns {
		if c.State == "ESTABLISHED" && IsInternalIP(c.RemoteAddress) && lateralPorts[c.RemotePort] {
			return true
		}
	}
	return false
}

func LocalTransportActivity(conns []netstat.ConnectionInfo) (bool, int) {
	count := 0
	for _, c := range conns {
		if c.State == "LISTENING" {
			continue
		}

		if c.State == "OTHER" {
			if (IsLoopbackIP(c.LocalAddress) && IsLoopbackIP(c.RemoteAddress)) ||
				(c.LocalAddress == c.RemoteAddress && IsInternalIP(c.LocalAddress)) {
				count++
				continue
			}
		}

		if c.State == "ESTABLISHED" {
			if (IsLoopbackIP(c.LocalAddress) && IsLoopbackIP(c.RemoteAddress)) ||
				(c.LocalAddress == c.RemoteAddress && IsInternalIP(c.LocalAddress)) {
				if c.LocalPort != c.RemotePort {
					count++
				}
			}
		}
	}
	return count > 0, count
}

func BuildCandidates(listeners []netstat.ListenerInfo, conns []netstat.ConnectionInfo, procMap map[int]*process.ProcessInfo) []Candidate {
	lmap := make(map[int][]netstat.ListenerInfo)
	for _, l := range listeners {
		lmap[l.Pid] = append(lmap[l.Pid], l)
	}
	cmap := make(map[int][]netstat.ConnectionInfo)
	for _, c := range conns {
		cmap[c.Pid] = append(cmap[c.Pid], c)
	}

	var cands []Candidate
	seen := make(map[int]bool)
	for pid := range lmap {
		seen[pid] = true
	}
	for pid := range cmap {
		seen[pid] = true
	}

	for pid := range seen {
		proc := procMap[pid]
		if proc == nil {
			continue
		}
		cands = append(cands, Candidate{
			Proc:      proc,
			Listeners: lmap[pid],
			Conns:     cmap[pid],
		})
	}
	return cands
}
