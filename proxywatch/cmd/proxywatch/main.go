//go:build windows
// +build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"golang.org/x/sys/windows"

	"proxywatch/internal/candidate"
	"proxywatch/internal/netstat"
	"proxywatch/internal/process"
	"proxywatch/internal/score"
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

// ---------------- Non-interactive compact table (for -once) ----------------

func printCompactTable(cands []candidate.Candidate, killScore int, doKill bool) {
	if len(cands) == 0 {
		fmt.Println("no candidates matching filters")
		return
	}

	fmt.Printf("%-6s %-22s %-26s %-7s %-9s %-7s\n",
		"PID", "NAME", "ROLE", "PROXY", "INT/EXT", "SCORE")
	fmt.Printf("%-6s %-22s %-26s %-7s %-9s %-7s\n",
		"-----", "----------------------", "--------------------------", "------", "---------", "------")

	for _, c := range cands {
		name := candidate.TrimName(c.Proc.Name, 22)
		intExt := fmt.Sprintf("%d/%d", c.OutInternal, c.OutExternal)

		fmt.Printf("%-6d %-22s %-26s %-7v %-9s %-7d\n",
			c.Proc.Pid, name, c.Role, c.ActiveProxying, intExt, c.Score)

		shouldKill := c.Score >= killScore
		if doKill && shouldKill {
			if err := killProcess(c.Proc.Pid); err != nil {
				fmt.Printf("[KILL-ERR] PID %d (%s): %v\n", c.Proc.Pid, c.Proc.Name, err)
			} else {
				fmt.Printf("[KILLED] PID %d (%s)\n", c.Proc.Pid, c.Proc.Name)
			}
		}
	}
}

// ---------------- Core scan / scoring ----------------

func runScan(minScore int, roleFilter map[string]bool) ([]candidate.Candidate, error) {
	listeners, conns, err := netstat.GetTCPTable()
	if err != nil {
		return nil, fmt.Errorf("failed to get TCP table: %w", err)
	}

	procMap, err := process.GetProcessInfoMap()
	if err != nil {
		return nil, fmt.Errorf("failed to get process info: %w", err)
	}

	cands := candidate.BuildCandidates(listeners, conns, procMap)
	var interesting []candidate.Candidate

	for i := range cands {
		score.ScoreCandidate(&cands[i])

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

	return interesting, nil
}

func killProcess(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

// ---------------- TUI App State ----------------

type AppMode int

const (
	modeDashboard AppMode = iota
	modeInspect
)

type AppState struct {
	screen tcell.Screen

	minScore    int
	killScore   int
	doKill      bool
	roleFilter  map[string]bool
	lastError   string
	lastUpdate  time.Time
	refreshInt  time.Duration
	candidates  []candidate.Candidate
	mode        AppMode
	selectedPID int
	selectedIdx int
	inspectPID  int

	killed map[int]bool
}

// ---------------- TUI helpers ----------------

func putString(s tcell.Screen, x, y int, text string) {
	for i, r := range text {
		s.SetContent(x+i, y, r, nil, tcell.StyleDefault)
	}
}

func (app *AppState) findIndexByPID(pid int) int {
	for i, c := range app.candidates {
		if c.Proc.Pid == pid {
			return i
		}
	}
	return -1
}

func (app *AppState) refresh() {
	cands, err := runScan(app.minScore, app.roleFilter)
	if err != nil {
		app.lastError = err.Error()
		app.candidates = nil
		app.lastUpdate = time.Now().UTC()
		return
	}

	if app.doKill {
		for _, c := range cands {
			if c.Score >= app.killScore && !app.killed[c.Proc.Pid] {
				if err := killProcess(c.Proc.Pid); err != nil {
					app.lastError = fmt.Sprintf("kill PID %d (%s): %v", c.Proc.Pid, c.Proc.Name, err)
				} else {
					app.killed[c.Proc.Pid] = true
				}
			}
		}
	}

	app.candidates = cands
	app.lastUpdate = time.Now().UTC()
	app.lastError = ""

	if len(app.candidates) == 0 {
		app.selectedIdx = -1
		app.selectedPID = 0
		return
	}

	if app.selectedPID != 0 {
		idx := app.findIndexByPID(app.selectedPID)
		if idx >= 0 {
			app.selectedIdx = idx
			return
		}
	}

	app.selectedIdx = 0
	app.selectedPID = app.candidates[0].Proc.Pid
}

func truncateToWidth(s string, w int) string {
	if w <= 0 || len(s) <= w {
		return s
	}
	if w <= 3 {
		return s[:w]
	}
	return s[:w-3] + "..."
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------- Dashboard ----------------

func (app *AppState) drawDashboard() {
	s := app.screen
	s.Clear()

	w, _ := s.Size()

	nowUTC := time.Now().UTC()
	header := fmt.Sprintf(
		"UTC: %s ",
		nowUTC.Format("2006-01-02 15:04:05"),
	)
	putString(s, 0, 0, truncateToWidth(header, w))

	putString(s, 0, 2, truncateToWidth("Use UP/DOWN arrows || ENTER to inspect || q to quit.", w))

	if app.lastError != "" {
		putString(s, 0, 3, truncateToWidth("Error: "+app.lastError, w))
	}

	y := 5

	if len(app.candidates) == 0 {
		putString(s, 0, y, "no candidates matching filters")
		return
	}

	putString(s, 0, y, fmt.Sprintf("%-1s %-6s %-22s %-26s %-7s %-9s %-7s",
		" ", "PID", "NAME", "ROLE", "PROXY", "INT/EXT", "SCORE"))
	y++
	putString(s, 0, y, fmt.Sprintf("%-1s %-6s %-22s %-26s %-7s %-9s %-7s",
		" ", "-----", "----------------------", "--------------------------", "------", "---------", "------"))
	y++

	for i, c := range app.candidates {
		arrow := " "
		if i == app.selectedIdx {
			arrow = ">"
		}
		name := candidate.TrimName(c.Proc.Name, 22)
		intExt := fmt.Sprintf("%d/%d", c.OutInternal, c.OutExternal)
		line := fmt.Sprintf("%-1s %-6d %-22s %-26s %-7v %-9s %-7d",
			arrow, c.Proc.Pid, name, c.Role, c.ActiveProxying, intExt, c.Score)
		putString(s, 0, y, truncateToWidth(line, w))
		y++
	}
}

// ---------------- Inspector ----------------

func (app *AppState) drawInspector() {
	s := app.screen
	s.Clear()
	w, h := s.Size()

	nowUTC := time.Now().UTC()
	header := fmt.Sprintf("UTC: %s", nowUTC.Format("2006-01-02 15:04:05"))
	putString(s, 0, 0, truncateToWidth(header, w))

	var cand *candidate.Candidate
	for i := range app.candidates {
		if app.candidates[i].Proc.Pid == app.inspectPID {
			cand = &app.candidates[i]
			break
		}
	}

	if cand == nil {
		putString(s, 0, 2, "Process no longer present. Press ESC.")
		return
	}

	y := 2
	title := fmt.Sprintf(" %s (PID %d) ", cand.Proc.Name, cand.Proc.Pid)
	sep := strings.Repeat("─", minInt(len(title), w))
	putString(s, 0, y, sep)
	y++
	putString(s, 0, y, truncateToWidth(title, w))
	y++
	putString(s, 0, y, sep)
	y += 2

	putString(s, 0, y, fmt.Sprintf("Role:  %s", cand.Role))
	y++
	putString(s, 0, y, fmt.Sprintf("Score: %d", cand.Score))
	y++
	putString(s, 0, y, fmt.Sprintf("Proxy: %v", cand.ActiveProxying))
	y++
	y++

	putString(s, 0, y, "Outbound:")
	y++
	putString(s, 2, y, fmt.Sprintf("Total: %d", cand.OutTotal))
	y++
	putString(s, 2, y, fmt.Sprintf("Internal: %d", cand.OutInternal))
	y++
	putString(s, 2, y, fmt.Sprintf("External: %d", cand.OutExternal))
	y++
	y++

	// -------------------
	// Active Connections
	// -------------------
	if len(cand.Conns) > 0 && y < h-6 {
		putString(s, 0, y, "Connections:")
		y++
		putString(s, 2, y, "Local                 Remote                State        Scope")
		y++
		putString(s, 2, y, "--------------------  --------------------  -----------  -------")
		y++

		maxRows := 8
		rows := 0
		for _, cn := range cand.Conns {
			if rows >= maxRows || y >= h-4 {
				break
			}
			scope := ""
			if cn.RemoteAddress != "" && !candidate.IsWildcardIP(cn.RemoteAddress) && !candidate.IsLoopbackIP(cn.RemoteAddress) {
				if candidate.IsInternalIP(cn.RemoteAddress) {
					scope = "internal"
				} else {
					scope = "external"
				}
			}
			l := fmt.Sprintf("%s:%d", cn.LocalAddress, cn.LocalPort)
			r := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
			line := fmt.Sprintf("%-20s %-20s %-11s %-7s", l, r, cn.State, scope)
			putString(s, 2, y, truncateToWidth(line, w-2))
			y++
			rows++
		}
		y++
	}

	// -------------------
	// Scoring Reasons
	// -------------------
	if len(cand.Reasons) > 0 && y < h-3 {
		putString(s, 0, y, "Scoring Reasons:")
		y++
		for _, r := range cand.Reasons {
			if y >= h-2 {
				break
			}
			putString(s, 0, y, truncateToWidth("  - "+r, w))
			y++
		}
	}

	if h > 0 {
		putString(s, 0, h-1, "ESC return | q quit")
	}
}

// ---------------- TUI main ----------------

func runTUI(minScore, killScore int, doKill bool, roleFilter map[string]bool) error {
	s, err := tcell.NewScreen()
	if err != nil {
		return err
	}
	if err := s.Init(); err != nil {
		return err
	}
	defer s.Fini()

	app := &AppState{
		screen:      s,
		minScore:    minScore,
		killScore:   killScore,
		doKill:      doKill,
		roleFilter:  roleFilter,
		refreshInt:  1 * time.Second,
		killed:      make(map[int]bool),
		selectedIdx: -1,
	}

	app.refresh()

	events := make(chan tcell.Event, 16)
	go func() {
		for {
			events <- s.PollEvent()
		}
	}()

	scanTicker := time.NewTicker(1 * time.Second)
	defer scanTicker.Stop()

	uiTicker := time.NewTicker(1 * time.Second)
	defer uiTicker.Stop()

	for {
		switch app.mode {
		case modeDashboard:
			app.drawDashboard()
		case modeInspect:
			app.drawInspector()
		}
		s.Show()

		select {
		case ev := <-events:
			switch tev := ev.(type) {
			case *tcell.EventResize:
				s.Sync()

			case *tcell.EventKey:
				switch app.mode {
				case modeDashboard:
					switch tev.Key() {
					case tcell.KeyUp:
						if app.selectedIdx > 0 {
							app.selectedIdx--
							app.selectedPID = app.candidates[app.selectedIdx].Proc.Pid
						}
					case tcell.KeyDown:
						if app.selectedIdx >= 0 && app.selectedIdx < len(app.candidates)-1 {
							app.selectedIdx++
							app.selectedPID = app.candidates[app.selectedIdx].Proc.Pid
						}
					case tcell.KeyEnter:
						if app.selectedIdx >= 0 && app.selectedIdx < len(app.candidates) {
							app.inspectPID = app.candidates[app.selectedIdx].Proc.Pid
							app.mode = modeInspect
						}
					}
					// No +/- here anymore
					if tev.Rune() == 'q' {
						return nil
					}

				case modeInspect:
					if tev.Key() == tcell.KeyEscape {
						app.mode = modeDashboard
					}
					if tev.Rune() == 'q' {
						return nil
					}
				}
			}

		case <-scanTicker.C:
			app.refresh()

		case <-uiTicker.C:
			// just cause redraw next loop
		}
	}
}

// ---------------- main ----------------

func main() {
	minScore := flag.Int("min", 15, "Minimum score to display a candidate")
	once := flag.Bool("once", false, "Run one scan and exit")
	roles := flag.String("roles", "", "Comma-separated list of roles to display")
	killScore := flag.Int("killScore", 80, "Score threshold for kill")
	doKill := flag.Bool("k", false, "Enable auto-kill")

	flag.Parse()

	roleFilter := parseRoleFilter(*roles)

	if *once {
		cands, err := runScan(*minScore, roleFilter)
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		printCompactTable(cands, *killScore, *doKill)
		return
	}

	if err := runTUI(*minScore, *killScore, *doKill, roleFilter); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}
