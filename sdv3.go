//go:build windows
// +build windows

package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ----------------------------
// Data models
// ----------------------------

type ProcessInfo struct {
	Pid  int
	Name string
}

type ListenerInfo struct {
	Pid          int
	LocalAddress string
	LocalPort    int
	State        string
}

type ConnectionInfo struct {
	Pid           int
	LocalAddress  string
	LocalPort     int
	RemoteAddress string
	RemotePort    int
	State         string
}

type Candidate struct {
	Proc           *ProcessInfo
	Listeners      []ListenerInfo
	Conns          []ConnectionInfo
	Score          int
	Reasons        []string
	ActiveProxying bool
	Role           string

	// Reverse-control / reverse-transport details
	ControlChannel         *ConnectionInfo
	ControlDurationSeconds int

	// Outbound stats (for clean summary display)
	OutTotal    int
	OutExternal int
	OutInternal int
}

// ----------------------------
// Config / heuristics
// ----------------------------

// Internal networks to treat as "inside"
var internalCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

// Lateral movement ports (still pure behavior)
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

// Persistent reverse-control tracking (stateful across scans)
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

// ----------------------------
// DLLs / syscalls
// ----------------------------

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcp = iphlpapi.NewProc("GetExtendedTcpTable")
)

// For GetExtendedTcpTable
const (
	AF_INET                 = 2
	AF_INET6                = 23
	TCP_TABLE_OWNER_PID_ALL = 5
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCP6RowOwnerPID struct {
	State         uint32
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	OwningPID     uint32
}

// ----------------------------
// Helpers
// ----------------------------

func isInternalIP(ip string) bool {
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

func isLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

func isWildcardIP(ip string) bool {
	return ip == "0.0.0.0" || ip == "::"
}

// Convert DWORD IPv4 address to dotted string (addr in network byte order)
func ipv4FromDWORD(addr uint32) string {
	b := []byte{
		byte(addr),
		byte(addr >> 8),
		byte(addr >> 16),
		byte(addr >> 24),
	}
	return net.IP(b).String()
}

// Network byte order to host for 16-bit port
func ntohs(p uint32) int {
	v := uint16(p)
	return int((v >> 8) | (v << 8))
}

func tcpStateToString(s uint32) string {
	switch s {
	case 2:
		return "LISTENING"
	case 5:
		return "ESTABLISHED"
	default:
		return "OTHER"
	}
}

func trimName(name string, max int) string {
	if len(name) <= max {
		return name
	}
	if max <= 3 {
		return name[:max]
	}
	return name[:max-3] + "..."
}

// ----------------------------
// TCP table: GetExtendedTcpTable (IPv4 + IPv6)
// ----------------------------

func getTCPTableForFamily(family uint32) ([]ListenerInfo, []ConnectionInfo, error) {
	var size uint32

	r0, _, _ := procGetExtendedTcp.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	const ERROR_INSUFFICIENT_BUFFER = 122
	if r0 != uintptr(ERROR_INSUFFICIENT_BUFFER) && r0 != 0 {
		return nil, nil, fmt.Errorf("GetExtendedTcpTable size query failed: %d", r0)
	}
	if size == 0 {
		return nil, nil, fmt.Errorf("GetExtendedTcpTable returned size 0")
	}

	buf := make([]byte, size)

	r0, _, e1 := procGetExtendedTcp.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	if r0 != 0 {
		return nil, nil, fmt.Errorf("GetExtendedTcpTable failed: %v (code=%d)", e1, r0)
	}

	bufPtr := uintptr(unsafe.Pointer(&buf[0]))
	numEntries := *(*uint32)(unsafe.Pointer(bufPtr))

	firstRowPtr := bufPtr + unsafe.Sizeof(numEntries)

	var listeners []ListenerInfo
	var conns []ConnectionInfo

	if family == AF_INET {
		rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
		for i := uint32(0); i < numEntries; i++ {
			rowPtr := firstRowPtr + uintptr(i)*rowSize
			row := (*mibTCPRowOwnerPID)(unsafe.Pointer(rowPtr))

			pid := int(row.OwningPID)
			lIP := ipv4FromDWORD(row.LocalAddr)
			rIP := ipv4FromDWORD(row.RemoteAddr)
			lPort := ntohs(row.LocalPort)
			rPort := ntohs(row.RemotePort)
			stateStr := tcpStateToString(row.State)

			if stateStr == "LISTENING" {
				listeners = append(listeners, ListenerInfo{
					Pid:          pid,
					LocalAddress: lIP,
					LocalPort:    lPort,
					State:        stateStr,
				})
			} else {
				conns = append(conns, ConnectionInfo{
					Pid:           pid,
					LocalAddress:  lIP,
					LocalPort:     lPort,
					RemoteAddress: rIP,
					RemotePort:    rPort,
					State:         stateStr,
				})
			}
		}
	} else if family == AF_INET6 {
		rowSize := unsafe.Sizeof(mibTCP6RowOwnerPID{})
		for i := uint32(0); i < numEntries; i++ {
			rowPtr := firstRowPtr + uintptr(i)*rowSize
			row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(rowPtr))

			pid := int(row.OwningPID)
			lIP := net.IP(row.LocalAddr[:]).String()
			rIP := net.IP(row.RemoteAddr[:]).String()
			lPort := ntohs(row.LocalPort)
			rPort := ntohs(row.RemotePort)
			stateStr := tcpStateToString(row.State)

			if stateStr == "LISTENING" {
				listeners = append(listeners, ListenerInfo{
					Pid:          pid,
					LocalAddress: lIP,
					LocalPort:    lPort,
					State:        stateStr,
				})
			} else {
				conns = append(conns, ConnectionInfo{
					Pid:           pid,
					LocalAddress:  lIP,
					LocalPort:     lPort,
					RemoteAddress: rIP,
					RemotePort:    rPort,
					State:         stateStr,
				})
			}
		}
	}

	return listeners, conns, nil
}

func getTCPTable() ([]ListenerInfo, []ConnectionInfo, error) {
	l4, c4, err := getTCPTableForFamily(AF_INET)
	if err != nil {
		return nil, nil, err
	}
	l6, c6, err := getTCPTableForFamily(AF_INET6)
	if err != nil {
		// If IPv6 fails, still return IPv4 data
		return l4, c4, nil
	}
	return append(l4, l6...), append(c4, c6...), nil
}

// ----------------------------
// Process info via tasklist (only PID + name)
// ----------------------------

func getProcessInfoMap() (map[int]*ProcessInfo, error) {
	cmd := exec.Command("tasklist", "/V", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tasklist failed: %w", err)
	}

	r := csv.NewReader(bytes.NewReader(out))
	r.FieldsPerRecord = -1

	m := make(map[int]*ProcessInfo)

	for {
		record, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("csv parse error: %w", err)
		}
		if len(record) < 2 {
			continue
		}

		name := strings.ToLower(strings.TrimSpace(record[0]))
		pidStr := strings.TrimSpace(record[1])

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		pi := &ProcessInfo{
			Pid:  pid,
			Name: name,
		}
		m[pid] = pi
	}

	return m, nil
}

// ----------------------------
// Candidate building
// ----------------------------

func buildCandidates(listeners []ListenerInfo, conns []ConnectionInfo, procMap map[int]*ProcessInfo) []Candidate {
	lmap := make(map[int][]ListenerInfo)
	for _, l := range listeners {
		lmap[l.Pid] = append(lmap[l.Pid], l)
	}
	cmap := make(map[int][]ConnectionInfo)
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

// ----------------------------
// Dynamic SOCKS / proxy indicators
// ----------------------------

func socksListenerPorts(listeners []ListenerInfo) (ports map[int]struct{}, loopbackOnly bool, anyWildcard bool) {
	ports = make(map[int]struct{})
	loopbackOnly = true
	anyWildcard = false

	for _, l := range listeners {
		ports[l.LocalPort] = struct{}{}

		if isWildcardIP(l.LocalAddress) {
			anyWildcard = true
			loopbackOnly = false
		} else if !isLoopbackIP(l.LocalAddress) {
			loopbackOnly = false
		}
	}
	return ports, loopbackOnly, anyWildcard
}

func countActiveClientSessions(conns []ConnectionInfo, listenPorts map[int]struct{}) (clients int, clientRemoteIPs map[string]int) {
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
		if c.RemoteAddress == "" || isWildcardIP(c.RemoteAddress) {
			continue
		}
		clients++
		clientRemoteIPs[c.RemoteAddress]++
	}
	return clients, clientRemoteIPs
}

func outboundTargets(conns []ConnectionInfo, listenPorts map[int]struct{}) (outTotal int, outExternal int, outInternal int) {
	for _, c := range conns {
		if c.State != "ESTABLISHED" {
			continue
		}
		if c.RemoteAddress == "" || isWildcardIP(c.RemoteAddress) || isLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := listenPorts[c.LocalPort]; ok {
			continue
		}

		outTotal++
		if isInternalIP(c.RemoteAddress) {
			outInternal++
		} else {
			outExternal++
		}
	}
	return outTotal, outExternal, outInternal
}

func hasInternalLateral(conns []ConnectionInfo) bool {
	for _, c := range conns {
		if c.State == "ESTABLISHED" && isInternalIP(c.RemoteAddress) && lateralPorts[c.RemotePort] {
			return true
		}
	}
	return false
}

// Combined (state + flow) local transport detection for reverse tunnels
func localTransportActivity(conns []ConnectionInfo) (bool, int) {
	count := 0
	for _, c := range conns {
		if c.State == "LISTENING" {
			continue
		}

		if c.State == "OTHER" {
			if (isLoopbackIP(c.LocalAddress) && isLoopbackIP(c.RemoteAddress)) ||
				(c.LocalAddress == c.RemoteAddress && isInternalIP(c.LocalAddress)) {
				count++
				continue
			}
		}

		if c.State == "ESTABLISHED" {
			if (isLoopbackIP(c.LocalAddress) && isLoopbackIP(c.RemoteAddress)) ||
				(c.LocalAddress == c.RemoteAddress && isInternalIP(c.LocalAddress)) {
				if c.LocalPort != c.RemotePort {
					count++
				}
			}
		}
	}
	return count > 0, count
}

// ----------------------------
// Scoring engine (behavior-only)
// ----------------------------

func ScoreCandidate(c *Candidate) {
	score := 0
	reasons := []string{}

	p := c.Proc

	ports, loopbackOnly, anyWildcard := socksListenerPorts(c.Listeners)
	hasListener := len(ports) > 0

	activeClients, clientIPs := countActiveClientSessions(c.Conns, ports)
	outTotal, outExternal, outInternal := outboundTargets(c.Conns, ports)

	// store outbound stats for UI
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
		if cn.RemoteAddress != "" && !isWildcardIP(cn.RemoteAddress) {
			key := cn.RemoteAddress + ":" + strconv.Itoa(cn.RemotePort)
			distinctTargets[key] = struct{}{}
			if cn.RemotePort > 0 {
				distinctTargetPorts[cn.RemotePort] = struct{}{}
			}
		}
	}

	numDistinctTargets := len(distinctTargets)

	// Track current ESTABLISHED connections for this PID in the reverseControlSeen map
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

	// Reverse-control / reverse-transport detection
	if !hasListener && outTotal == 1 && numDistinctTargets == 1 {
		var rcConn *ConnectionInfo
		for _, cn := range c.Conns {
			if cn.State != "ESTABLISHED" {
				continue
			}
			if cn.RemoteAddress == "" || isWildcardIP(cn.RemoteAddress) || isLoopbackIP(cn.RemoteAddress) {
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

					localTransport, localTransCount := localTransportActivity(c.Conns)

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

						score = baseScore + durPoints + localPoints

						reasons = append(reasons,
							"Reverse transport tunnel in use (persistent reverse channel + local TCP transport activity)",
							fmt.Sprintf("Persistent reverse control channel %s:%d -> %s:%d (~%ds)",
								rcConn.LocalAddress, rcConn.LocalPort,
								rcConn.RemoteAddress, rcConn.RemotePort,
								secs),
							fmt.Sprintf("Local transport connections observed (approx count: %d)", localTransCount),
						)
						if isInternalIP(rcConn.RemoteAddress) {
							reasons = append(reasons, "Control endpoint is internal")
						} else {
							reasons = append(reasons, "Control endpoint is external")
						}

						c.Score = score
						c.Reasons = reasons
						c.Role = "reverse-transport"
						c.ActiveProxying = true
						c.ControlChannel = rcConn
						c.ControlDurationSeconds = secs
						return
					}

					// Idle reverse-control
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

	// ----------------------------
	// Core behavioral scoring
	// ----------------------------

	if hasListener {
		score += 5
		reasons = append(reasons, "Process has TCP listener(s)")
		if loopbackOnly {
			reasons = append(reasons, "Listener is loopback-only")
		}
		if anyWildcard {
			reasons = append(reasons, "Listener bound to wildcard address")
		}
	}

	if totalEstab >= 2 {
		score += 15
		reasons = append(reasons, fmt.Sprintf("Multiple established connections (%d)", totalEstab))
	}
	if totalEstab >= 4 {
		score += 25
		reasons = append(reasons, "High degree of connection multiplexing")
	}
	if totalEstab >= 8 {
		score += 40
		reasons = append(reasons, "Very high degree of connection multiplexing")
	}

	if outTotal > 0 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("Outbound connections to remote targets (%d)", outTotal))
	}
	if outTotal >= 3 {
		score += 30
		reasons = append(reasons, "Multiple outbound target connections (tunnel/proxy pattern)")
	}
	if outTotal >= 6 {
		score += 50
		reasons = append(reasons, "Heavy outbound target fan-out")
	}

	if numDistinctTargets >= 2 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("Distinct remote endpoints: %d", numDistinctTargets))
	}
	if numDistinctTargets >= 5 {
		score += 40
		reasons = append(reasons, "High variety of remote endpoints")
	}

	numDistinctPorts := len(distinctTargetPorts)
	if numDistinctPorts >= 3 {
		score += 25
		reasons = append(reasons, fmt.Sprintf("Multiple remote service ports observed (%d)", numDistinctPorts))
	}

	if activeClients > 0 {
		score += 25
		reasons = append(reasons, fmt.Sprintf("Active client sessions connected to listener (%d)", activeClients))

		nonLoopClients := 0
		for ip := range clientIPs {
			if !isLoopbackIP(ip) {
				nonLoopClients++
			}
		}
		if nonLoopClients > 0 {
			score += 25
			reasons = append(reasons, fmt.Sprintf("Listener has non-loopback clients (%d)", nonLoopClients))
		}
	}

	activeProxyingListener := hasListener && activeClients > 0 && outTotal > 0
	if activeProxyingListener {
		score += 60
		reasons = append(reasons, "Active proxying via listener: client(s) + outbound target connections")
	}

	reverseTunnelPattern := !hasListener && outTotal >= 3 && numDistinctTargets >= 2
	if reverseTunnelPattern {
		score += 50
		reasons = append(reasons, "Reverse tunnel pattern: multiple outbound targets, no listener")
	}

	if outExternal > 0 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("Connections to external destinations (%d)", outExternal))
	}
	if outInternal > 0 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("Connections to internal destinations (%d)", outInternal))
	}

	if hasInternalLateral(c.Conns) {
		score += 25
		reasons = append(reasons, "Internal connections to common lateral-movement ports")
	}

	if hasListener && activeClients == 0 && outTotal == 0 {
		score -= 10
		reasons = append(reasons, "Listener with no active sessions and no outbound targets (likely idle)")
	}

	if score < 0 {
		score = 0
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

	c.Score = score
	c.Reasons = reasons
	c.Role = role
	c.ActiveProxying = activeProxyingListener || reverseTunnelPattern
}

// ----------------------------
// Scanning + main
// ----------------------------

func parseRoleFilter(s string) map[string]bool {
	res := make(map[string]bool)
	if s == "" {
		return res
	}
	for _, part := range strings.Split(s, ",") {
		role := strings.TrimSpace(part)
		if role == "" {
			continue
		}
		res[role] = true
	}
	return res
}

func runScan(minScore int, roleFilter map[string]bool) []Candidate {
	listeners, conns, err := getTCPTable()
	if err != nil {
		fmt.Printf("error: failed to get TCP table: %v\n", err)
		return nil
	}

	procMap, err := getProcessInfoMap()
	if err != nil {
		fmt.Printf("error: failed to get process info: %v\n", err)
		return nil
	}

	cands := buildCandidates(listeners, conns, procMap)
	var interesting []Candidate

	for i := range cands {
		ScoreCandidate(&cands[i])

		// Role filter: if set, only show requested roles
		if len(roleFilter) > 0 {
			if _, ok := roleFilter[cands[i].Role]; !ok {
				continue
			}
		}

		if cands[i].Score >= minScore || cands[i].Role == "reverse-control" {
			interesting = append(interesting, cands[i])
		}
	}

	sort.Slice(interesting, func(i, j int) bool {
		if interesting[i].Score == interesting[j].Score {
			return interesting[i].Proc.Pid < interesting[j].Proc.Pid
		}
		return interesting[i].Score > interesting[j].Score
	})

	return interesting
}

// ----------------------------
// Killing
// ----------------------------

func killProcess(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

// ----------------------------
// Main
// ----------------------------

func main() {
	minScore := flag.Int("min", 15, "Minimum score to display a candidate (reverse-control always shown)")
	once := flag.Bool("once", false, "Run one scan and exit")
	interval := flag.Int("interval", 5, "Interval in seconds between scans in continuous mode")
	roles := flag.String("roles", "", "Comma-separated list of roles to display (others hidden)")
	killScore := flag.Int("killScore", 80, "Score threshold at or above which kill may trigger")
	doKill := flag.Bool("k", false, "If set, kill processes with score >= killScore")

	flag.Parse()

	roleFilter := parseRoleFilter(*roles)

	printSummary := func(cands []Candidate, killScore int, doKill bool) {
		if len(cands) == 0 {
			fmt.Println("no candidates matching filters")
			return
		}

		// summary header
		fmt.Printf("%-6s %-18s %-18s %-7s %-9s %-7s %-6s\n",
			"PID", "NAME", "ROLE", "SCORE", "INT/EXT", "PROXY", "KILL")

		for _, c := range cands {
			name := trimName(c.Proc.Name, 18)
			intExt := fmt.Sprintf("%d/%d", c.OutInternal, c.OutExternal)

			killMark := "-"
			shouldKill := c.Score >= killScore
			if shouldKill {
				killMark = "YES"
			}

			fmt.Printf("%-6d %-18s %-18s %-7d %-9s %-7v %-6s\n",
				c.Proc.Pid,
				name,
				c.Role,
				c.Score,
				intExt,
				c.ActiveProxying,
				killMark,
			)

			if doKill && shouldKill {
				if err := killProcess(c.Proc.Pid); err != nil {
					fmt.Printf("[KILL-ERR] PID %d (%s): %v\n", c.Proc.Pid, c.Proc.Name, err)
				} else {
					fmt.Printf("[KILLED] PID %d (%s)\n", c.Proc.Pid, c.Proc.Name)
				}
			}
		}
	}

	printDetails := func(cands []Candidate) {
		for _, c := range cands {
			fmt.Println()
			fmt.Printf("[PID %d] %s\n", c.Proc.Pid, c.Proc.Name)
			fmt.Printf("  Role: %s  Score: %d  ActiveProxying: %v\n",
				c.Role, c.Score, c.ActiveProxying)

			if c.OutTotal > 0 {
				fmt.Printf("  Outbound: total=%d internal=%d external=%d\n",
					c.OutTotal, c.OutInternal, c.OutExternal)
			}

			if (c.Role == "reverse-control" || c.Role == "reverse-transport") && c.ControlChannel != nil {
				scope := "external"
				if isInternalIP(c.ControlChannel.RemoteAddress) {
					scope = "internal"
				}
				fmt.Printf("  Control: %s:%d -> %s:%d (%ds, %s)\n",
					c.ControlChannel.LocalAddress, c.ControlChannel.LocalPort,
					c.ControlChannel.RemoteAddress, c.ControlChannel.RemotePort,
					c.ControlDurationSeconds,
					scope,
				)
			}

			if len(c.Listeners) > 0 {
				fmt.Println("  Listeners:")
				for _, l := range c.Listeners {
					fmt.Printf("    - %s:%d (%s)\n", l.LocalAddress, l.LocalPort, l.State)
				}
			}

			if len(c.Conns) > 0 {
				fmt.Println("  Connections:")
				for _, cn := range c.Conns {
					scope := ""
					if cn.RemoteAddress != "" && !isWildcardIP(cn.RemoteAddress) && !isLoopbackIP(cn.RemoteAddress) {
						if isInternalIP(cn.RemoteAddress) {
							scope = "internal"
						} else {
							scope = "external"
						}
					}
					if scope != "" {
						fmt.Printf("    - %s:%d -> %s:%d (%s, %s)\n",
							cn.LocalAddress, cn.LocalPort,
							cn.RemoteAddress, cn.RemotePort,
							cn.State, scope)
					} else {
						fmt.Printf("    - %s:%d -> %s:%d (%s)\n",
							cn.LocalAddress, cn.LocalPort,
							cn.RemoteAddress, cn.RemotePort,
							cn.State)
					}
				}
			}

			if len(c.Reasons) > 0 {
				fmt.Println("  Reasons:")
				for _, r := range c.Reasons {
					fmt.Printf("    - %s\n", r)
				}
			}
		}
	}

	doScan := func() {
		cands := runScan(*minScore, roleFilter)
		if len(cands) == 0 {
			fmt.Println("no candidates matching filters")
			return
		}
		printSummary(cands, *killScore, *doKill)
		printDetails(cands)
	}

	if *once {
		doScan()
		return
	}

	for {
		doScan()
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}
