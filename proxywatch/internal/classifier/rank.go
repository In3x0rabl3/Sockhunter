package classifier

import (
	"fmt"
	"time"

	"proxywatch/internal/shared"
)

func ScoreCandidate(c *shared.Candidate) {
	scoreVal := 0
	reasons := []string{}
	signals := []string{}
	addSignal := func(s string) {
		for _, existing := range signals {
			if existing == s {
				return
			}
		}
		signals = append(signals, s)
	}

	p := c.Proc
	now := time.Now()
	hist := getHistory(p.Pid, now)
	updateConnHistory(p.Pid, c.Conns, now)

	ports, loopbackOnly, anyWildcard := socksListenerPorts(c.Listeners)
	hasListener := len(ports) > 0

	activeClients, _ := countActiveClientSessions(c.Conns, ports)
	outTotal, outExternal, outInternal, outLoopback := outboundTargets(c.Conns, ports)
	outLongLived, outShortLived := outboundConnAgeStats(c.Conns, ports, now)

	c.OutTotal = outTotal
	c.OutExternal = outExternal
	c.OutInternal = outInternal
	c.OutLoopback = outLoopback
	c.OutLongLived = outLongLived
	c.OutShortLived = outShortLived
	c.InboundTotal = activeClients

	if activeClients > 0 {
		addSignal("inbound-active")
		shared.RecentClientSeen[p.Pid] = now
	}
	if outTotal > 0 {
		addSignal("outbound-active")
		shared.RecentOutboundSeen[p.Pid] = now
	}
	if outInternal > 0 {
		addSignal("outbound-internal")
	}
	if outExternal > 0 {
		addSignal("outbound-external")
	}
	if outLoopback > 0 {
		addSignal("outbound-loopback")
	}
	if outLongLived > 0 {
		addSignal("outbound-long-lived")
	}
	if outShortLived > 0 && outLongLived == 0 {
		addSignal("outbound-bursty")
	}

	inboundRecent := activeClients > 0
	if t, ok := shared.RecentClientSeen[p.Pid]; ok && now.Sub(t) <= shared.ActiveWindow {
		inboundRecent = true
	}

	outboundRecent := outTotal > 0
	if t, ok := shared.RecentOutboundSeen[p.Pid]; ok && now.Sub(t) <= shared.ActiveWindow {
		outboundRecent = true
	}

	forwardActiveNow := hasListener && inboundRecent && outboundRecent

	controlConn, controlSecs := findPersistentControl(p.Pid, c.Conns, now)
	if controlConn != nil {
		addSignal("control-channel")
		c.ControlChannel = controlConn
		c.ControlDurationSeconds = controlSecs
	}

	reverseProxyNow := false

	outboundActive, distinctTargets, distinctTargetPorts := outboundActivity(c.Conns, ports)
	internalTargets, internalPorts, internalLateral := outboundInternalSummary(c.Conns, ports)
	reverseTunnelEligible := internalLateral ||
		len(internalTargets) >= shared.MinInternalTargetsForRev ||
		len(internalPorts) >= shared.MinInternalPortsForRev

	localTransport, localCount := localTransportActivity(c.Conns)
	if localTransport {
		addSignal("loopback-transport")
	}

	tunnelLikely := !hasListener && outTotal > 0 && outLongLived > 0 && localTransport

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

	if reverseProxyNow {
		addSignal("reverse-proxy-active")
	}

	if forwardActiveNow || reverseProxyNow {
		hist.LastActive = now
	}

	if reverseProxyNow {
		hist.LastSuspicious = now
		hist.SuspicionKind = shared.SuspicionProxy
		if hist.StickyScore < shared.ReverseStickyScore {
			hist.StickyScore = shared.ReverseStickyScore
		}
	} else if forwardActiveNow {
		if hist.StickyScore < shared.ForwardStickyScore {
			hist.StickyScore = shared.ForwardStickyScore
		}
	}

	activeRecent := !hist.LastActive.IsZero() && now.Sub(hist.LastActive) <= shared.ActiveHoldWindow
	suspiciousRecent := !hist.LastSuspicious.IsZero() && now.Sub(hist.LastSuspicious) <= shared.SuspicionWindow

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
				addSignal("reverse-transport")
				c.Signals = signals
				c.Confidence = confidenceFor(c.Role, c.Score, c.ActiveProxying)
				return
			}
		}
	}
	if reverseControl {
		addSignal("reverse-control")
	}

	// ---------------- Heuristics ----------------

	if hasListener {
		scoreVal += 5
		addSignal("listener")
		reasons = append(reasons, "Process has TCP listener(s)")
		if loopbackOnly {
			addSignal("listener-loopback")
			reasons = append(reasons, "Listener is loopback-only")
		}
		if anyWildcard {
			addSignal("listener-wildcard")
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

	if outLongLived > 0 {
		scoreVal += 10
		reasons = append(reasons, "Long-lived outbound connection(s)")
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
		addSignal("internal-lateral")
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

	if tunnelLikely && !reverseProxyNow && !reverseControl {
		c.Role = "tunnel-likely"
		c.ActiveProxying = true
		addSignal("tunnel-likely")
		base := 60 + min(outLongLived*5, 25)
		if c.Score < base {
			c.Score = base
		}
		c.Reasons = append(c.Reasons, "Long-lived outbound connection with local loopback transport")
	}

	if c.Role == "outbound-only" &&
		outInternal == 0 &&
		!hasListener &&
		!reverseProxyNow &&
		!reverseControl {
		if c.Score > shared.OutboundOnlyExternalCap {
			c.Score = shared.OutboundOnlyExternalCap
			c.Reasons = append(c.Reasons, "External-only outbound traffic de-emphasized")
		}
	}

	if reverseProxyNow || (suspiciousRecent && hist.SuspicionKind == shared.SuspicionProxy) {
		c.Role = "reverse-proxy"
		if hist.StickyScore > c.Score {
			c.Score = hist.StickyScore
		}
		if reverseProxyNow {
			c.Reasons = append(c.Reasons, "Persistent control channel with proxied outbound activity")
		}
		addSignal("reverse-proxy")
	} else if reverseControl || (suspiciousRecent && hist.SuspicionKind == shared.SuspicionControl) {
		c.Role = "reverse-control"
		c.ActiveProxying = false
		c.Reasons = []string{
			"Persistent reverse control channel detected",
		}

		if reverseControl {
			base := controlStickyScore(controlSecs)
			if hist.StickyScore < base {
				hist.StickyScore = base
			}
			hist.LastSuspicious = now
			hist.SuspicionKind = shared.SuspicionControl
		}
		if hist.StickyScore > c.Score {
			c.Score = hist.StickyScore
		}
		addSignal("reverse-control")
	}

	c.Signals = signals
	c.Confidence = confidenceFor(c.Role, c.Score, c.ActiveProxying)

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
) (total, external, internal, loopback int) {

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) {
			continue
		}
		if shared.IsLoopbackIP(c.RemoteAddress) {
			loopback++
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

func outboundConnAgeStats(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
	now time.Time,
) (longLived int, shortLived int) {
	for _, c := range conns {
		if !isEstablishedState(c.State) {
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

		key := connKeyFromConn(c.Pid, c)
		first, ok := shared.ConnFirstSeen[key]
		if !ok {
			continue
		}
		age := now.Sub(first)
		if age >= shared.LongLivedOutboundMinAge {
			longLived++
		}
		if age <= shared.ShortLivedOutboundMaxAge {
			shortLived++
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
	exclude *shared.ConnKey,
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

func connKeyFromConn(pid int, cn shared.ConnectionInfo) shared.ConnKey {
	return shared.ConnKey{
		Pid:        pid,
		LocalAddr:  cn.LocalAddress,
		LocalPort:  cn.LocalPort,
		RemoteAddr: cn.RemoteAddress,
		RemotePort: cn.RemotePort,
	}
}

func updateConnHistory(pid int, conns []shared.ConnectionInfo, now time.Time) {
	current := make(map[shared.ConnKey]struct{})
	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		key := connKeyFromConn(pid, cn)
		current[key] = struct{}{}
		if _, ok := shared.ConnFirstSeen[key]; !ok {
			shared.ConnFirstSeen[key] = now
		}
	}

	for k := range shared.ConnFirstSeen {
		if k.Pid == pid {
			if _, ok := current[k]; !ok {
				delete(shared.ConnFirstSeen, k)
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
		first, ok := shared.ConnFirstSeen[key]
		if !ok {
			continue
		}
		age := now.Sub(first)
		if age >= shared.ReverseControlMinDuration && age > bestAge {
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

func getHistory(pid int, now time.Time) *shared.ProcHistory {
	h := shared.ProcHistoryByPID[pid]
	if h == nil {
		h = &shared.ProcHistory{}
		shared.ProcHistoryByPID[pid] = h
	}
	h.LastSeen = now
	return h
}

func purgeHistory(now time.Time) {
	if !shared.LastHistoryCleanup.IsZero() && now.Sub(shared.LastHistoryCleanup) < shared.CleanupInterval {
		return
	}
	shared.LastHistoryCleanup = now

	for pid, h := range shared.ProcHistoryByPID {
		if now.Sub(h.LastSeen) <= shared.HistoryTTL {
			continue
		}

		delete(shared.ProcHistoryByPID, pid)
		delete(shared.RecentClientSeen, pid)
		delete(shared.RecentOutboundSeen, pid)

		for k := range shared.ConnFirstSeen {
			if k.Pid == pid {
				delete(shared.ConnFirstSeen, k)
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
		return shared.ReverseControlBaseScore
	}
}

func confidenceFor(role string, score int, active bool) int {
	base := 10
	switch role {
	case "reverse-transport":
		base = 85
	case "reverse-proxy":
		base = 80
	case "reverse-control":
		base = 75
	case "tunnel-likely":
		base = 65
	case "proxy-listener":
		base = 60
	case "reverse-tunnel":
		base = 55
	case "listener-with-clients":
		base = 50
	case "listener-with-outbound":
		base = 45
	case "listener-only":
		base = 35
	case "outbound-only":
		base = 30
	case "no-network-activity":
		base = 5
	}

	if active {
		base += 5
	}

	conf := base + (score / 4)
	if conf > 100 {
		return 100
	}
	if conf < 0 {
		return 0
	}
	return conf
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
	return shared.BenignControlPorts[port]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
