//go:build windows
// +build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"proxywatch/internal/classifier"
	"proxywatch/internal/telemetry"
	"proxywatch/internal/ui"
)

/* ---------------- CLI helpers ---------------- */

func parseRoleFilter(s string) map[string]bool {
	out := make(map[string]bool)
	if s == "" {
		return out
	}
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			out[r] = true
		}
	}
	return out
}

/* ---------------- Scanner adapter ---------------- */

// scanner bridges telemetry + classifier into the UI refresh loop.
type scanner struct {
	minScore   int
	roleFilter map[string]bool
}

func (s *scanner) Refresh(app *ui.AppState) {
	snap, err := telemetry.Collect()
	if err != nil {
		app.LastError = err.Error()
		app.Candidates = nil
		app.SelectedIdx = -1
		app.SelectedPID = 0
		app.LastUpdate = time.Now().UTC()
		return
	}

	cands := classifier.Classify(snap, s.minScore, s.roleFilter)

	app.Candidates = cands
	app.LastUpdate = time.Now().UTC()
	app.LastError = ""

	// maintain selection across refreshes
	if len(app.Candidates) == 0 {
		app.SelectedIdx = -1
		app.SelectedPID = 0
		return
	}

	if app.SelectedPID != 0 {
		for i, c := range app.Candidates {
			if c.Proc.Pid == app.SelectedPID {
				app.SelectedIdx = i
				return
			}
		}
	}

	app.SelectedIdx = 0
	app.SelectedPID = app.Candidates[0].Proc.Pid
}

/* ---------------- main ---------------- */

func main() {
	minScore := flag.Int("min", 15, "Minimum score to display a candidate")
	once := flag.Bool("once", false, "Run one scan and exit")
	roles := flag.String("roles", "", "Comma-separated list of roles to display")
	interval := flag.Duration("interval", 1*time.Second, "Refresh interval (e.g. 250ms, 1s)")

	flag.Parse()

	roleFilter := parseRoleFilter(*roles)

	// -------- one-shot mode --------
	if *once {
		snap, err := telemetry.Collect()
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}

		cands := classifier.Classify(snap, *minScore, roleFilter)

		// intentionally minimal, machine-friendly output
		for _, c := range cands {
			fmt.Printf(
				"pid=%d role=%s active=%v out_int=%d out_ext=%d\n",
				c.Proc.Pid,
				c.Role,
				c.ActiveProxying,
				c.OutInternal,
				c.OutExternal,
			)
		}

		return
	}

	// -------- interactive TUI --------
	app := &ui.AppState{
		MinScore:   *minScore,
		RoleFilter: roleFilter,
		RefreshInt: *interval,
	}

	sc := &scanner{
		minScore:   *minScore,
		roleFilter: roleFilter,
	}

	if err := ui.Run(app, sc); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}
