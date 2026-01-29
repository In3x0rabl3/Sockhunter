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
	app.SelectedIdx = -1
	app.Mode = shared.ModeDashboard

	scanner.Refresh(app)

	events := make(chan tcell.Event, 16)
	go func() {
		for {
			events <- s.PollEvent()
		}
	}()

	tick := time.NewTicker(app.RefreshInt)
	defer tick.Stop()

	for {
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
					if tev.Key() == tcell.KeyEscape {
						app.Mode = shared.ModeDashboard
					}
					if tev.Rune() == 'q' {
						return nil
					}
					if tev.Rune() == 'k' || tev.Rune() == 'K' {
						pid := app.InspectPID
						idx := FindIndexByPID(app, pid)
						if idx == -1 {
							app.LastError = "Process no longer present"
							break
						}

						if err := telemetry.KillProcess(pid); err != nil {
							app.LastError = "Kill failed: " + err.Error()
						} else {
							app.LastError = "Killed PID " + strconv.Itoa(pid) + " (" + app.Candidates[idx].Proc.Name + ")"
						}
					}
				}
			}

		case <-tick.C:
			scanner.Refresh(app)
		}
	}
}
