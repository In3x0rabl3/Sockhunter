//go:build windows
// +build windows

package score

import (
	"fmt"
	"time"

	"proxywatch/internal/candidate"
	"proxywatch/internal/netstat"
)

type ConnKey struct {
	Pid        int
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
}

var (
	reverseControlSeen        = make(map[ConnKey]time.Time)
	reverseControlMinDuration = 10 * time.Second
)

func ScoreCandidate(c *candidate.Candidate) {
	scoreVal := 0
	reasons := []string{}

	p := c.Proc

	ports, loopbackOnly, anyWildcard := candidate.SocksListenerPorts(c.Listeners)
	hasListener := len(ports) > 0

	activeClients, clientIPs := candidate.CountActiveClientSessions(c.Conns, ports)
	outTotal, outExternal, outInternal := candidate.OutboundTargets(c.Conns, ports)

	c.OutTotal = outTotal
	c.OutExternal = outExternal
	c.OutInternal = outInternal

	totalEstab := 0
	distinctTargets := make(map[string]struct{})
	distinctTargetPorts := make(map[int]struct{})

	for _, cn := range c.Conns {
		if cn.State != "ESTABLISHED" {
			continue
		}
		totalEstab++
		if cn.RemoteAddress != "" && !candidate.IsWildcardIP(cn.RemoteAddress) {
			key := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
			distinctTargets[key] = struct{}{}
			if cn.RemotePort > 0 {
				distinctTargetPorts[cn.RemotePort] = struct{}{}
			}
		}
	}

	numDistinctTargets := len(distinctTargets)

	currentKeys := make(map[ConnKey]struct{})
	for _, cn := range c.Conns {
		if cn.State != "ESTABLISHED" {
			continue
		}
		key := ConnKey{
			Pid:        p.Pid,
			LocalAddr:  cn.LocalAddress,
			LocalPort:  cn.LocalPort,
			RemoteAddr: cn.RemoteAddress,
			RemotePort: cn.RemotePort,
		}
		currentKeys[key] = struct{}{}
	}
	for k := range reverseControlSeen {
		if k.Pid == p.Pid {
			if _, ok := currentKeys[k]; !ok {
				delete(reverseControlSeen, k)
			}
		}
	}

	if !hasListener && outTotal == 1 && numDistinctTargets == 1 {
		var rcConn *netstat.ConnectionInfo
		for _, cn := range c.Conns {
			if cn.State != "ESTABLISHED" {
				continue
			}
			if cn.RemoteAddress == "" || candidate.IsWildcardIP(cn.RemoteAddress) || candidate.IsLoopbackIP(cn.RemoteAddress) {
				continue
			}
			cp := cn
			rcConn = &cp
			break
		}

		if rcConn != nil {
			key := ConnKey{
				Pid:        p.Pid,
				LocalAddr:  rcConn.LocalAddress,
				LocalPort:  rcConn.LocalPort,
				RemoteAddr: rcConn.RemoteAddress,
				RemotePort: rcConn.RemotePort,
			}
			now := time.Now()
			first, ok := reverseControlSeen[key]
			if !ok {
				reverseControlSeen[key] = now
			} else {
				dur := now.Sub(first)
				if dur >= reverseControlMinDuration {
					secs := int(dur.Seconds())

					localTransport, localTransCount := candidate.LocalTransportActivity(c.Conns)

					if localTransport {
						baseScore := 60
						durPoints := (secs / 10) * 5
						if durPoints > 40 {
							durPoints = 40
						}

						localPoints := 0
						if localTransCount > 0 {
							localPoints += 20
							if localTransCount > 3 {
								localPoints += 20
							}
						}

						scoreVal = baseScore + durPoints + localPoints

						reasons = append(reasons,
							"Reverse transport tunnel in use (persistent reverse channel + local TCP transport activity)",
							fmt.Sprintf("Persistent reverse control channel %s:%d -> %s:%d (~%ds)",
								rcConn.LocalAddress, rcConn.LocalPort,
								rcConn.RemoteAddress, rcConn.RemotePort,
								secs),
							fmt.Sprintf("Local transport connections observed (approx count: %d)", localTransCount),
						)
						if candidate.IsInternalIP(rcConn.RemoteAddress) {
							reasons = append(reasons, "Control endpoint is internal")
						} else {
							reasons = append(reasons, "Control endpoint is external")
						}

						c.Score = scoreVal
						c.Reasons = reasons
						c.Role = "reverse-transport"
						c.ActiveProxying = true
						c.ControlChannel = rcConn
						c.ControlDurationSeconds = secs
						return
					}

					c.Score = 0
					c.Role = "reverse-control"
					c.ActiveProxying = false
					c.Reasons = []string{
						"Persistent reverse control channel detected (no local proxying yet)",
						fmt.Sprintf("Channel %s:%d -> %s:%d active for ~%ds",
							rcConn.LocalAddress, rcConn.LocalPort,
							rcConn.RemoteAddress, rcConn.RemotePort,
							secs),
					}
					c.ControlChannel = rcConn
					c.ControlDurationSeconds = secs
					return
				}
			}
		}
	}

	if hasListener {
		scoreVal += 5
		reasons = append(reasons, "Process has TCP listener(s)")
		if loopbackOnly {
			reasons = append(reasons, "Listener is loopback-only")
		}
		if anyWildcard {
			reasons = append(reasons, "Listener bound to wildcard address")
		}
	}

	if totalEstab >= 2 {
		scoreVal += 15
		reasons = append(reasons, fmt.Sprintf("Multiple established connections (%d)", totalEstab))
	}
	if totalEstab >= 4 {
		scoreVal += 25
		reasons = append(reasons, "High degree of connection multiplexing")
	}
	if totalEstab >= 8 {
		scoreVal += 40
		reasons = append(reasons, "Very high degree of connection multiplexing")
	}

	if outTotal > 0 {
		scoreVal += 20
		reasons = append(reasons, fmt.Sprintf("Outbound connections to remote targets (%d)", outTotal))
	}
	if outTotal >= 3 {
		scoreVal += 30
		reasons = append(reasons, "Multiple outbound target connections (tunnel/proxy pattern)")
	}
	if outTotal >= 6 {
		scoreVal += 50
		reasons = append(reasons, "Heavy outbound target fan-out")
	}

	if numDistinctTargets >= 2 {
		scoreVal += 20
		reasons = append(reasons, fmt.Sprintf("Distinct remote endpoints: %d", numDistinctTargets))
	}
	if numDistinctTargets >= 5 {
		scoreVal += 40
		reasons = append(reasons, "High variety of remote endpoints")
	}

	numDistinctPorts := len(distinctTargetPorts)
	if numDistinctPorts >= 3 {
		scoreVal += 25
		reasons = append(reasons, fmt.Sprintf("Multiple remote service ports observed (%d)", numDistinctPorts))
	}

	if activeClients > 0 {
		scoreVal += 25
		reasons = append(reasons, fmt.Sprintf("Active client sessions connected to listener (%d)", activeClients))

		nonLoopClients := 0
		for ip := range clientIPs {
			if !candidate.IsLoopbackIP(ip) {
				nonLoopClients++
			}
		}
		if nonLoopClients > 0 {
			scoreVal += 25
			reasons = append(reasons, fmt.Sprintf("Listener has non-loopback clients (%d)", nonLoopClients))
		}
	}

	activeProxyingListener := hasListener && activeClients > 0 && outTotal > 0
	if activeProxyingListener {
		scoreVal += 60
		reasons = append(reasons, "Active proxying via listener: client(s) + outbound target connections")
	}

	reverseTunnelPattern := !hasListener && outTotal >= 3 && numDistinctTargets >= 2
	if reverseTunnelPattern {
		scoreVal += 50
		reasons = append(reasons, "Reverse tunnel pattern: multiple outbound targets, no listener")
	}

	if outExternal > 0 {
		scoreVal += 10
		reasons = append(reasons, fmt.Sprintf("Connections to external destinations (%d)", outExternal))
	}
	if outInternal > 0 {
		scoreVal += 10
		reasons = append(reasons, fmt.Sprintf("Connections to internal destinations (%d)", outInternal))
	}

	if candidate.HasInternalLateral(c.Conns) {
		scoreVal += 25
		reasons = append(reasons, "Internal connections to common lateral-movement ports")
	}

	if hasListener && activeClients == 0 && outTotal == 0 {
		scoreVal -= 10
		reasons = append(reasons, "Listener with no active sessions and no outbound targets (likely idle)")
	}

	if scoreVal < 0 {
		scoreVal = 0
	}

	role := "no-network-activity"
	switch {
	case hasListener && activeClients > 0 && outTotal > 0:
		role = "proxy-listener"
	case hasListener && activeClients > 0 && outTotal == 0:
		role = "listener-with-clients"
	case hasListener && activeClients == 0 && outTotal > 0:
		role = "listener-with-outbound"
	case hasListener && activeClients == 0 && outTotal == 0:
		role = "listener-only"
	case !hasListener && outTotal >= 3:
		role = "reverse-tunnel"
	case !hasListener && outTotal > 0:
		role = "outbound-only"
	default:
		role = "no-network-activity"
	}

	c.Score = scoreVal
	c.Reasons = reasons
	c.Role = role
	c.ActiveProxying = activeProxyingListener || reverseTunnelPattern
}