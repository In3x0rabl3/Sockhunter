package ui

import (
	"fmt"
	"time"

	"proxywatch/internal/shared"
)

func DrawDashboard(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, _ := s.Size()
	nowUTC := time.Now().UTC()

	PutString(s, 0, 0,
		TruncateToWidth(fmt.Sprintf("UTC: %s", nowUTC.Format("2006-01-02 15:04:05")), w),
	)

	PutString(s, 0, 2,
		TruncateToWidth("Use UP/DOWN arrows | ENTER inspect | q quit", w),
	)

	if app.LastError != "" {
		PutString(s, 0, 3, TruncateToWidth("Status: "+app.LastError, w))
	}

	y := 5
	if len(app.Candidates) == 0 {
		PutString(s, 0, y, "no candidates matching filters")
		return
	}

	PutString(s, 0, y,
		fmt.Sprintf("%-1s %-6s %-22s %-26s %-7s %-9s",
			" ", "PID", "NAME", "ROLE", "ACTIVE", "INT/EXT"),
	)
	y++
	PutString(s, 0, y,
		fmt.Sprintf("%-1s %-6s %-22s %-26s %-7s %-9s",
			" ", "-----", "----------------------", "--------------------------", "------", "---------"),
	)
	y++

	for i, c := range app.Candidates {
		arrow := " "
		if i == app.SelectedIdx {
			arrow = ">"
		}

		name := shared.TrimName(c.Proc.Name, 22)
		intExt := fmt.Sprintf("%d/%d", c.OutInternal, c.OutExternal)

		line := fmt.Sprintf("%-1s %-6d %-22s %-26s %-7v %-9s",
			arrow,
			c.Proc.Pid,
			name,
			c.Role,
			c.ActiveProxying,
			intExt,
		)

		PutString(s, 0, y, TruncateToWidth(line, w))
		y++
	}
}
