package ui

import (
	"strconv"
	"time"

	"proxywatch/internal/shared"
	"proxywatch/internal/telemetry"

	"github.com/gdamore/tcell/v2"
)

func Run(app *shared.AppState, scanner shared.Scanner) error {
	s, err := tcell.NewScreen()
	if err != nil {
		return err
	}
	if err := s.Init(); err != nil {
		return err
	}
	defer s.Fini()

	app.Screen = s
	if app.RefreshInt <= 0 {
		app.RefreshInt = 1 * time.Second
	}
	if app.ConfirmKillTimeout <= 0 {
		app.ConfirmKillTimeout = 3 * time.Second
	}
	app.SelectedIdx = -1
	app.Mode = shared.ModeDashboard

	scanner.Refresh(app)

	events := make(chan tcell.Event, 16)
	go func() {
		for {
			events <- s.PollEvent()
		}
	}()

	type refreshResult struct {
		candidates          []shared.Candidate
		lastError           string
		lastUpdate          time.Time
		selectedPID         int
		selectedIdx         int
		selectionPIDAtStart int
	}

	refreshCh := make(chan refreshResult, 1)
	refreshInFlight := false
	startRefresh := func() {
		if refreshInFlight {
			return
		}
		refreshInFlight = true
		selectionPIDAtStart := app.SelectedPID
		go func() {
			tmp := *app
			tmp.Screen = nil
			scanner.Refresh(&tmp)
			refreshCh <- refreshResult{
				candidates:          tmp.Candidates,
				lastError:           tmp.LastError,
				lastUpdate:          tmp.LastUpdate,
				selectedPID:         tmp.SelectedPID,
				selectedIdx:         tmp.SelectedIdx,
				selectionPIDAtStart: selectionPIDAtStart,
			}
		}()
	}

	tick := time.NewTicker(app.RefreshInt)
	defer tick.Stop()

	for {
		if app.ConfirmKillPID != 0 && time.Now().After(app.ConfirmKillDeadline) {
			app.ConfirmKillPID = 0
		}

		switch app.Mode {
		case shared.ModeDashboard:
			DrawDashboard(app)
		case shared.ModeInspect:
			DrawInspector(app)
		}
		s.Show()

		select {
		case ev := <-events:
			switch tev := ev.(type) {
			case *tcell.EventResize:
				s.Sync()

			case *tcell.EventKey:
				switch app.Mode {

				case shared.ModeDashboard:
					switch tev.Key() {
					case tcell.KeyUp:
						if len(app.Candidates) > 0 &&
							app.SelectedIdx > 0 &&
							app.SelectedIdx < len(app.Candidates) {
							app.SelectedIdx--
							app.SelectedPID = app.Candidates[app.SelectedIdx].Proc.Pid
						}
					case tcell.KeyDown:
						if app.SelectedIdx >= 0 &&
							app.SelectedIdx < len(app.Candidates)-1 {
							app.SelectedIdx++
							app.SelectedPID = app.Candidates[app.SelectedIdx].Proc.Pid
						}
					case tcell.KeyEnter:
						if app.SelectedIdx >= 0 &&
							app.SelectedIdx < len(app.Candidates) {
							app.InspectPID = app.Candidates[app.SelectedIdx].Proc.Pid
							app.Mode = shared.ModeInspect
						}
					}

					if tev.Rune() == 'q' {
						return nil
					}

				case shared.ModeInspect:
					if app.ConfirmKillPID != 0 {
						if r := tev.Rune(); r != 'k' && r != 'K' && r != 'y' && r != 'Y' {
							app.ConfirmKillPID = 0
						}
					}
					if tev.Key() == tcell.KeyEscape {
						app.ConfirmKillPID = 0
						app.Mode = shared.ModeDashboard
					}
					if tev.Rune() == 'q' {
						app.ConfirmKillPID = 0
						return nil
					}
					if tev.Rune() == 'k' || tev.Rune() == 'K' || tev.Rune() == 'y' || tev.Rune() == 'Y' {
						pid := app.InspectPID
						if app.ConfirmKill {
							if app.ConfirmKillPID != pid || time.Now().After(app.ConfirmKillDeadline) {
								if tev.Rune() == 'y' || tev.Rune() == 'Y' {
									break
								}
								app.ConfirmKillPID = pid
								app.ConfirmKillDeadline = time.Now().Add(app.ConfirmKillTimeout)
								break
							}
						}

						idx := FindIndexByPID(app.Candidates, pid)
						if idx == -1 {
							app.LastError = "Process no longer present"
							app.ConfirmKillPID = 0
							break
						}

						if err := telemetry.KillProcess(pid); err != nil {
							app.LastError = "Kill failed: " + err.Error()
						} else {
							app.LastError = "Killed PID " + strconv.Itoa(pid) + " (" + app.Candidates[idx].Proc.Name + ")"
						}
						app.ConfirmKillPID = 0
					}
				}
			}

		case <-tick.C:
			startRefresh()
		case res := <-refreshCh:
			refreshInFlight = false
			app.Candidates = res.candidates
			app.LastError = res.lastError
			app.LastUpdate = res.lastUpdate

			if len(app.Candidates) == 0 {
				app.SelectedIdx = -1
				app.SelectedPID = 0
				break
			}

			if app.SelectedPID != res.selectionPIDAtStart {
				idx := FindIndexByPID(app.Candidates, app.SelectedPID)
				if idx >= 0 {
					app.SelectedIdx = idx
				} else {
					app.SelectedIdx = 0
					app.SelectedPID = app.Candidates[0].Proc.Pid
				}
				break
			}

			app.SelectedPID = res.selectedPID
			app.SelectedIdx = res.selectedIdx
		}
	}
}
