package ui

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"
)

func DrawInspector(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, h := s.Size()
	nowUTC := time.Now().UTC()

	PutString(s, 0, 0,
		TruncateToWidth(fmt.Sprintf("UTC: %s", nowUTC.Format("2006-01-02 15:04:05")), w),
	)

	var cand *shared.Candidate
	for i := range app.Candidates {
		if app.Candidates[i].Proc.Pid == app.InspectPID {
			cand = &app.Candidates[i]
			break
		}
	}

	if cand == nil {
		PutString(s, 0, 2, "Process no longer present. Press ESC.")
		return
	}

	y := 2
	title := fmt.Sprintf(" %s (PID %d) ", cand.Proc.Name, cand.Proc.Pid)
	sep := strings.Repeat("─", MinInt(len(title), w))

	PutString(s, 0, y, sep)
	y++
	PutString(s, 0, y, TruncateToWidth(title, w))
	y++
	PutString(s, 0, y, sep)
	y += 2

	PutString(s, 0, y, fmt.Sprintf("Role:  %s", cand.Role))
	y++
	PutString(s, 0, y, fmt.Sprintf("Active: %v", cand.ActiveProxying))
	y += 2

	PutString(s, 0, y, "Process:")
	y++

	user := cand.Proc.UserName
	if user == "" {
		user = "(unknown)"
	}
	PutString(s, 2, y, TruncateToWidth(fmt.Sprintf("User: %s", user), w-2))
	y++

	sessionName := cand.Proc.SessionName
	if sessionName == "" && cand.Proc.SessionID != 0 {
		sessionName = fmt.Sprintf("Session-%d", cand.Proc.SessionID)
	}
	if sessionName == "" {
		sessionName = "(unknown)"
	}
	PutString(s, 2, y, TruncateToWidth(fmt.Sprintf("Session: %s (%d)", sessionName, cand.Proc.SessionID), w-2))
	y++

	parentPID := "unknown"
	if cand.Proc.ParentPid > 0 {
		parentPID = fmt.Sprintf("%d", cand.Proc.ParentPid)
	}
	PutString(s, 2, y, fmt.Sprintf("Parent PID: %s", parentPID))
	y++

	path := cand.Proc.ExePath
	if path == "" {
		path = "(unknown)"
	}
	PutString(s, 2, y, TruncateToWidth(fmt.Sprintf("Path: %s", path), w-2))
	y++

	integrity := cand.Proc.Integrity
	if integrity == "" {
		integrity = "(unknown)"
	}
	PutString(s, 2, y, fmt.Sprintf("Integrity: %s", integrity))
	y += 2

	established := 0
	for _, cn := range cand.Conns {
		if cn.State == "ESTABLISHED" {
			established++
		}
	}

	PutString(s, 0, y, "Networking:")
	y++
	PutString(s, 2, y, fmt.Sprintf("Inbound: %d  Outbound: %d", cand.InboundTotal, cand.OutTotal))
	y++
	PutString(s, 2, y, fmt.Sprintf("Listeners: %d  Established: %d", len(cand.Listeners), established))
	y++
	PutString(s, 2, y,
		TruncateToWidth(
			fmt.Sprintf(
				"IO bytes: %s",
				FormatIOBytes(cand.Proc.IOReadBytes, cand.Proc.IOWriteBytes, cand.Proc.IOOtherBytes),
			),
			w-2,
		),
	)
	y++
	PutString(s, 2, y,
		TruncateToWidth(
			fmt.Sprintf(
				"IO rate:  %s",
				FormatIORate(cand.Proc.IOReadBps, cand.Proc.IOWriteBps, cand.Proc.IOOtherBps),
			),
			w-2,
		),
	)
	y++
	y++

	if len(cand.Conns) > 0 && y < h-6 {
		PutString(s, 0, y, "Connections:")
		y++
		PutString(s, 2, y, "Local                 Remote                State        Scope")
		y++
		PutString(s, 2, y, "--------------------  --------------------  -----------  -------")
		y++

		for _, cn := range cand.Conns {
			if y >= h-3 {
				break
			}

			scope := ""
			if cn.RemoteAddress != "" &&
				!shared.IsWildcardIP(cn.RemoteAddress) &&
				!shared.IsLoopbackIP(cn.RemoteAddress) {

				if shared.IsInternalIP(cn.RemoteAddress) {
					scope = "internal"
				} else {
					scope = "external"
				}
			}

			l := fmt.Sprintf("%s:%d", cn.LocalAddress, cn.LocalPort)
			r := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
			line := fmt.Sprintf("%-20s %-20s %-11s %-7s", l, r, cn.State, scope)

			PutString(s, 2, y, TruncateToWidth(line, w-2))
			y++
		}
	}

	if app.LastError != "" && h >= 2 {
		PutString(s, 0, h-2, TruncateToWidth("Status: "+app.LastError, w))
	}

	PutString(s, 0, h-1, "ESC return | k kill | q quit")
}
