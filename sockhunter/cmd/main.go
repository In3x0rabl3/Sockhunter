//go:build windows
// +build windows

package main

import (
	"flag"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

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

func killProcess(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

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
				c.Proc.Pid, name, c.Role, c.Score, intExt, c.ActiveProxying, killMark)

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
			fmt.Printf("  Role: %s  Score: %d  ActiveProxying: %v\n", c.Role, c.Score, c.ActiveProxying)

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
					c.ControlDurationSeconds, scope)
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
