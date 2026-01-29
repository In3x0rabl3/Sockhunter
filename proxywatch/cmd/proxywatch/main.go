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
	"proxywatch/internal/shared"
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

/* ---------------- main ---------------- */

func main() {
	once := flag.Bool("once", false, "Run one scan and exit")
	roles := flag.String("roles", "", "Comma-separated list of roles to display")
	interval := flag.Duration("interval", 1*time.Second, "Refresh interval (e.g. 250ms, 1s)")

	flag.Parse()

	roleFilter := parseRoleFilter(*roles)
	minScore := 15

	// -------- one-shot mode --------
	if *once {
		snap, err := telemetry.Collect()
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}

		cands := classifier.Classify(snap, minScore, roleFilter)

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
	app := &shared.AppState{
		RefreshInt: *interval,
	}

	sc := &shared.ScannerAdapter{
		MinScore:   minScore,
		RoleFilter: roleFilter,
		Collect:    telemetry.Collect,
		Classify:   classifier.Classify,
	}

	if err := ui.Run(app, sc); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}
