package ui

import (
	"time"

	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

type AppMode int

const (
	ModeDashboard AppMode = iota
	ModeInspect
)

type AppState struct {
	Screen tcell.Screen

	MinScore   int
	KillScore  int
	DoKill     bool
	RoleFilter map[string]bool

	LastError  string
	LastUpdate time.Time
	RefreshInt time.Duration

	Candidates  []shared.Candidate
	Mode        AppMode
	SelectedPID int
	SelectedIdx int
	InspectPID  int

	Killed map[int]bool
}

/* ---------- helpers ---------- */

func PutString(s tcell.Screen, x, y int, text string) {
	for i, r := range text {
		s.SetContent(x+i, y, r, nil, tcell.StyleDefault)
	}
}

func (app *AppState) FindIndexByPID(pid int) int {
	for i, c := range app.Candidates {
		if c.Proc.Pid == pid {
			return i
		}
	}
	return -1
}

func TruncateToWidth(s string, w int) string {
	if w <= 0 || len(s) <= w {
		return s
	}
	if w <= 3 {
		return s[:w]
	}
	return s[:w-3] + "..."
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
