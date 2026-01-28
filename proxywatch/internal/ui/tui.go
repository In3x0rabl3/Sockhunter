package ui

import (
	"time"

	"github.com/gdamore/tcell/v2"
)

type Scanner interface {
	Refresh(app *AppState)
}

func Run(app *AppState, scanner Scanner) error {
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
	app.Killed = make(map[int]bool)
	app.SelectedIdx = -1
	app.Mode = ModeDashboard

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
		case ModeDashboard:
			app.DrawDashboard()
		case ModeInspect:
			app.DrawInspector()
		}
		s.Show()

		select {
		case ev := <-events:
			switch tev := ev.(type) {
			case *tcell.EventResize:
				s.Sync()

			case *tcell.EventKey:
				switch app.Mode {

				case ModeDashboard:
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
							app.Mode = ModeInspect
						}
					}

					if tev.Rune() == 'q' {
						return nil
					}

				case ModeInspect:
					if tev.Key() == tcell.KeyEscape {
						app.Mode = ModeDashboard
					}
					if tev.Rune() == 'q' {
						return nil
					}
				}
			}

		case <-tick.C:
			scanner.Refresh(app)
		}
	}
}
