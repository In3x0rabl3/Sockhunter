package classifier

import (
	"fmt"
	"time"

	"proxywatch/internal/shared"
)

type ConnKey struct {
	Pid        int
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
}

type procHistory struct {
	lastSeen       time.Time
	lastActive     time.Time
	lastSuspicious time.Time
	suspicionKind  int
	stickyScore    int
}

const (
	suspicionNone = iota
	suspicionControl
	suspicionProxy
)

var (
	reverseControlSeen        = make(map[ConnKey]time.Time)
	reverseControlMinDuration = 10 * time.Second
	recentClientSeen          = make(map[int]time.Time)
	recentOutboundSeen        = make(map[int]time.Time)
	activeWindow              = 10 * time.Second
	activeHoldWindow          = 30 * time.Second
	suspicionWindow           = 5 * time.Minute
	historyTTL                = 5 * time.Minute
	cleanupInterval           = 30 * time.Second
	reverseStickyScore        = 90
	forwardStickyScore        = 70
	reverseControlBaseScore   = 40
	minInternalTargetsForRev  = 2
	minInternalPortsForRev    = 2
	outboundOnlyExternalCap   = 30
	procHistoryByPID          = make(map[int]*procHistory)
	lastHistoryCleanup        time.Time
	benignControlPorts        = map[int]bool{
		53:   true,
		80:   true,
		443:  true,
		8080: true,
		8443: true,
		8000: true,
		8001: true,
		8008: true,
		8888: true,
	}
)

func ScoreCandidate(c *shared.Candidate) {
	scoreVal := 0
	reasons := []string{}

	p := c.Proc
	now := time.Now()
	hist := getHistory(p.Pid, now)
	updateConnHistory(p.Pid, c.Conns, now)

	ports, loopbackOnly, anyWildcard := socksListenerPorts(c.Listeners)
	hasListener := len(ports) > 0

	activeClients, _ := countActiveClientSessions(c.Conns, ports)
	outTotal, outExternal, outInternal := outboundTargets(c.Conns, ports)

	c.OutTotal = outTotal
	c.OutExternal = outExternal
	c.OutInternal = outInternal
	c.InboundTotal = activeClients

	if activeClients > 0 {
		recentClientSeen[p.Pid] = now
	}
	if outTotal > 0 {
		recentOutboundSeen[p.Pid] = now
	}

	inboundRecent := activeClients > 0
	if t, ok := recentClientSeen[p.Pid]; ok && now.Sub(t) <= activeWindow {
		inboundRecent = true
	}

	outboundRecent := outTotal > 0
	if t, ok := recentOutboundSeen[p.Pid]; ok && now.Sub(t) <= activeWindow {
		outboundRecent = true
	}

	forwardActiveNow := hasListener && inboundRecent && outboundRecent

	controlConn, controlSecs := findPersistentControl(p.Pid, c.Conns, now)
	if controlConn != nil {
		c.ControlChannel = controlConn
		c.ControlDurationSeconds = controlSecs
	}

	reverseProxyNow := false

	outboundActive, distinctTargets, distinctTargetPorts := outboundActivity(c.Conns, ports)
	internalTargets, internalPorts, internalLateral := outboundInternalSummary(c.Conns, ports)
	reverseTunnelEligible := internalLateral ||
		len(internalTargets) >= minInternalTargetsForRev ||
		len(internalPorts) >= minInternalPortsForRev

	if controlConn != nil && !hasListener {
		controlKey := connKeyFromConn(p.Pid, *controlConn)
		proxyOutTotal, _, _ := outboundTargetsExcluding(c.Conns, ports, &controlKey)
		if proxyOutTotal > 0 && reverseTunnelEligible {
			reverseProxyNow = true
		}
	}

	if !reverseProxyNow && !hasListener && outInternal > 0 && reverseTunnelEligible {
		reverseProxyNow = true
	}

	if forwardActiveNow || reverseProxyNow {
		hist.lastActive = now
	}

	if reverseProxyNow {
		hist.lastSuspicious = now
		hist.suspicionKind = suspicionProxy
		if hist.stickyScore < reverseStickyScore {
			hist.stickyScore = reverseStickyScore
		}
	} else if forwardActiveNow {
		if hist.stickyScore < forwardStickyScore {
			hist.stickyScore = forwardStickyScore
		}
	}

	activeRecent := !hist.lastActive.IsZero() && now.Sub(hist.lastActive) <= activeHoldWindow
	suspiciousRecent := !hist.lastSuspicious.IsZero() && now.Sub(hist.lastSuspicious) <= suspicionWindow

	activeProxying := forwardActiveNow || reverseProxyNow || activeRecent

	// ---------------- Reverse control detection ----------------
	reverseControl := false
	if !hasListener && outTotal == 1 && len(distinctTargets) == 1 && controlConn != nil {
		if isLikelyBenignControlPort(controlConn.RemotePort) && !internalLateral && outInternal == 0 {
			reverseControl = false
		} else {
			reverseControl = true
		}
		if reverseControl {
			localTransport, localCount := localTransportActivity(c.Conns)
			if localTransport {
				scoreVal = 60 + min((controlSecs/10)*5, 40)
				if localCount > 0 {
					scoreVal += 20
					if localCount > 3 {
						scoreVal += 20
					}
				}

				c.Score = scoreVal
				c.Role = "reverse-transport"
				c.ActiveProxying = true
				c.ControlChannel = controlConn
				c.ControlDurationSeconds = controlSecs
				c.Reasons = []string{
					"Persistent reverse control channel with local transport activity",
				}
				return
			}
		}
	}

	// ---------------- Heuristics ----------------

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

	if outboundActive >= 2 {
		scoreVal += 15
	}
	if outboundActive >= 4 {
		scoreVal += 25
	}
	if outboundActive >= 8 {
		scoreVal += 40
	}

	if outTotal > 0 {
		scoreVal += 20
	}
	if outTotal >= 3 {
		scoreVal += 30
	}
	if outTotal >= 6 {
		scoreVal += 50
	}

	if len(distinctTargets) >= 2 {
		scoreVal += 20
	}
	if len(distinctTargets) >= 5 {
		scoreVal += 40
	}

	if len(distinctTargetPorts) >= 3 {
		scoreVal += 25
	}

	if activeClients > 0 {
		scoreVal += 25
	}

	if internalLateral {
		scoreVal += 25
	}

	if hasListener && activeClients == 0 && outTotal == 0 {
		scoreVal -= 10
	}

	if scoreVal < 0 {
		scoreVal = 0
	}

	c.Score = scoreVal
	c.Reasons = reasons
	c.ActiveProxying = activeProxying
	c.Role = deriveRole(hasListener, activeClients, outTotal, reverseTunnelEligible)

	if c.Role == "outbound-only" &&
		outInternal == 0 &&
		!hasListener &&
		!reverseProxyNow &&
		!reverseControl {
		if c.Score > outboundOnlyExternalCap {
			c.Score = outboundOnlyExternalCap
			c.Reasons = append(c.Reasons, "External-only outbound traffic de-emphasized")
		}
	}

	if reverseProxyNow || (suspiciousRecent && hist.suspicionKind == suspicionProxy) {
		c.Role = "reverse-proxy"
		if hist.stickyScore > c.Score {
			c.Score = hist.stickyScore
		}
		if reverseProxyNow {
			c.Reasons = append(c.Reasons, "Persistent control channel with proxied outbound activity")
		}
	} else if reverseControl || (suspiciousRecent && hist.suspicionKind == suspicionControl) {
		c.Role = "reverse-control"
		c.ActiveProxying = false
		c.Reasons = []string{
			"Persistent reverse control channel detected",
		}

		if reverseControl {
			base := controlStickyScore(controlSecs)
			if hist.stickyScore < base {
				hist.stickyScore = base
			}
			hist.lastSuspicious = now
			hist.suspicionKind = suspicionControl
		}
		if hist.stickyScore > c.Score {
			c.Score = hist.stickyScore
		}
	}

	purgeHistory(now)
}

/* ---------------- helpers ---------------- */

func deriveRole(hasListener bool, clients int, out int, reverseTunnelEligible bool) string {
	switch {
	case hasListener && clients > 0 && out > 0:
		return "proxy-listener"
	case hasListener && clients > 0:
		return "listener-with-clients"
	case hasListener && out > 0:
		return "listener-with-outbound"
	case hasListener:
		return "listener-only"
	case out >= 3 && reverseTunnelEligible:
		return "reverse-tunnel"
	case out > 0:
		return "outbound-only"
	default:
		return "no-network-activity"
	}
}

func socksListenerPorts(listeners []shared.ListenerInfo) (map[int]struct{}, bool, bool) {
	ports := make(map[int]struct{})
	loopbackOnly := true
	anyWildcard := false

	for _, l := range listeners {
		ports[l.LocalPort] = struct{}{}
		if shared.IsWildcardIP(l.LocalAddress) {
			anyWildcard = true
			loopbackOnly = false
		} else if !shared.IsLoopbackIP(l.LocalAddress) {
			loopbackOnly = false
		}
	}
	return ports, loopbackOnly, anyWildcard
}

func countActiveClientSessions(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (int, map[string]int) {

	ips := make(map[string]int)
	count := 0

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if _, ok := ports[c.LocalPort]; !ok {
			continue
		}
		if c.RemoteAddress == "" || shared.IsWildcardIP(c.RemoteAddress) {
			continue
		}
		count++
		ips[c.RemoteAddress]++
	}
	return count, ips
}

func outboundTargets(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (total, external, internal int) {

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		total++
		if shared.IsInternalIP(c.RemoteAddress) {
			internal++
		} else {
			external++
		}
	}
	return
}

func outboundActivity(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (total int, distinctTargets map[string]struct{}, distinctPorts map[int]struct{}) {
	distinctTargets = make(map[string]struct{})
	distinctPorts = make(map[int]struct{})

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		total++
		key := fmt.Sprintf("%s:%d", c.RemoteAddress, c.RemotePort)
		distinctTargets[key] = struct{}{}
		if c.RemotePort > 0 {
			distinctPorts[c.RemotePort] = struct{}{}
		}
	}
	return
}

func outboundInternalSummary(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (internalTargets map[string]struct{}, internalPorts map[int]struct{}, internalLateral bool) {
	internalTargets = make(map[string]struct{})
	internalPorts = make(map[int]struct{})

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}
		if !shared.IsInternalIP(c.RemoteAddress) {
			continue
		}

		internalTargets[c.RemoteAddress] = struct{}{}
		if c.RemotePort > 0 {
			internalPorts[c.RemotePort] = struct{}{}
			if shared.LateralPorts[c.RemotePort] {
				internalLateral = true
			}
		}
	}
	return
}

func outboundTargetsExcluding(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
	exclude *ConnKey,
) (total, external, internal int) {

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if exclude != nil && *exclude == connKeyFromConn(c.Pid, c) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		total++
		if shared.IsInternalIP(c.RemoteAddress) {
			internal++
		} else {
			external++
		}
	}
	return
}

func hasInternalLateral(conns []shared.ConnectionInfo) bool {
	for _, c := range conns {
		if isActiveConnState(c.State) &&
			shared.IsInternalIP(c.RemoteAddress) &&
			shared.LateralPorts[c.RemotePort] {
			return true
		}
	}
	return false
}

func localTransportActivity(conns []shared.ConnectionInfo) (bool, int) {
	count := 0
	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if shared.IsLoopbackIP(c.LocalAddress) &&
			shared.IsLoopbackIP(c.RemoteAddress) &&
			c.LocalPort != c.RemotePort {
			count++
		}
	}
	return count > 0, count
}

func connKeyFromConn(pid int, cn shared.ConnectionInfo) ConnKey {
	return ConnKey{
		Pid:        pid,
		LocalAddr:  cn.LocalAddress,
		LocalPort:  cn.LocalPort,
		RemoteAddr: cn.RemoteAddress,
		RemotePort: cn.RemotePort,
	}
}

func updateConnHistory(pid int, conns []shared.ConnectionInfo, now time.Time) {
	current := make(map[ConnKey]struct{})
	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		key := connKeyFromConn(pid, cn)
		current[key] = struct{}{}
		if _, ok := reverseControlSeen[key]; !ok {
			reverseControlSeen[key] = now
		}
	}

	for k := range reverseControlSeen {
		if k.Pid == pid {
			if _, ok := current[k]; !ok {
				delete(reverseControlSeen, k)
			}
		}
	}
}

func findPersistentControl(pid int, conns []shared.ConnectionInfo, now time.Time) (*shared.ConnectionInfo, int) {
	var best *shared.ConnectionInfo
	var bestAge time.Duration

	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		if cn.RemoteAddress == "" ||
			shared.IsWildcardIP(cn.RemoteAddress) ||
			shared.IsLoopbackIP(cn.RemoteAddress) {
			continue
		}

		key := connKeyFromConn(pid, cn)
		first, ok := reverseControlSeen[key]
		if !ok {
			continue
		}
		age := now.Sub(first)
		if age >= reverseControlMinDuration && age > bestAge {
			tmp := cn
			best = &tmp
			bestAge = age
		}
	}

	if best == nil {
		return nil, 0
	}
	return best, int(bestAge.Seconds())
}

func getHistory(pid int, now time.Time) *procHistory {
	h := procHistoryByPID[pid]
	if h == nil {
		h = &procHistory{}
		procHistoryByPID[pid] = h
	}
	h.lastSeen = now
	return h
}

func purgeHistory(now time.Time) {
	if !lastHistoryCleanup.IsZero() && now.Sub(lastHistoryCleanup) < cleanupInterval {
		return
	}
	lastHistoryCleanup = now

	for pid, h := range procHistoryByPID {
		if now.Sub(h.lastSeen) <= historyTTL {
			continue
		}

		delete(procHistoryByPID, pid)
		delete(recentClientSeen, pid)
		delete(recentOutboundSeen, pid)

		for k := range reverseControlSeen {
			if k.Pid == pid {
				delete(reverseControlSeen, k)
			}
		}
	}
}

func controlStickyScore(controlSecs int) int {
	switch {
	case controlSecs >= 300:
		return 85
	case controlSecs >= 120:
		return 70
	case controlSecs >= 60:
		return 60
	default:
		return reverseControlBaseScore
	}
}

func isEstablishedState(state string) bool {
	return state == "ESTABLISHED"
}

func isActiveConnState(state string) bool {
	switch state {
	case "ESTABLISHED",
		"SYN_SENT",
		"SYN_RECEIVED",
		"FIN_WAIT_1",
		"FIN_WAIT_2",
		"CLOSE_WAIT",
		"CLOSING",
		"LAST_ACK",
		"TIME_WAIT":
		return true
	default:
		return false
	}
}

func isLikelyBenignControlPort(port int) bool {
	return benignControlPorts[port]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
