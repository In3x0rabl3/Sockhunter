package shared

import (
	"time"

	"github.com/gdamore/tcell/v2"
)

type AppMode int

const (
	ModeDashboard AppMode = iota
	ModeInspect
)

type AppState struct {
	Screen tcell.Screen

	LastError           string
	LastUpdate          time.Time
	RefreshInt          time.Duration
	ConfirmKill         bool
	ConfirmKillTimeout  time.Duration
	ConfirmKillPID      int
	ConfirmKillDeadline time.Time

	Candidates  []Candidate
	Mode        AppMode
	SelectedPID int
	SelectedIdx int
	InspectPID  int
}

type Scanner interface {
	Refresh(app *AppState)
}

type IOSample struct {
	Read      uint64
	Write     uint64
	Other     uint64
	Timestamp time.Time
}

type ScannerAdapter struct {
	Options  ClassifyOptions
	Cache    ClassifierCache
	LastIO   map[int]IOSample
	Logger   *JSONLogger
	Collect  func() (*Snapshot, error)
	Classify ClassifyFunc
}

func (s *ScannerAdapter) Refresh(app *AppState) {
	if s.Collect == nil || s.Classify == nil {
		app.LastError = "scanner not configured"
		app.Candidates = nil
		app.SelectedIdx = -1
		app.SelectedPID = 0
		app.LastUpdate = time.Now().UTC()
		return
	}

	snap, err := s.Collect()
	if err != nil {
		app.LastError = err.Error()
		app.Candidates = nil
		app.SelectedIdx = -1
		app.SelectedPID = 0
		app.LastUpdate = time.Now().UTC()
		return
	}

	cands := s.Classify(snap, s.Options, &s.Cache)
	now := time.Now().UTC()
	applyIORates(cands, now, &s.LastIO)

	app.LastError = ""
	if s.Logger != nil {
		if err := s.Logger.WriteSnapshot(snap, cands); err != nil {
			app.LastError = "log write failed: " + err.Error()
		}
	}

	app.Candidates = cands
	app.LastUpdate = now
	// app.LastError already set above

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

func applyIORates(cands []Candidate, now time.Time, prev *map[int]IOSample) {
	if *prev == nil {
		*prev = make(map[int]IOSample, len(cands))
	}

	next := make(map[int]IOSample, len(cands))
	for i := range cands {
		pi := cands[i].Proc
		if pi == nil {
			continue
		}

		sample := IOSample{
			Read:      pi.IOReadBytes,
			Write:     pi.IOWriteBytes,
			Other:     pi.IOOtherBytes,
			Timestamp: now,
		}

		if p, ok := (*prev)[pi.Pid]; ok && now.After(p.Timestamp) {
			dt := now.Sub(p.Timestamp).Seconds()
			if dt > 0 {
				if pi.IOReadBytes >= p.Read {
					pi.IOReadBps = uint64(float64(pi.IOReadBytes-p.Read) / dt)
				}
				if pi.IOWriteBytes >= p.Write {
					pi.IOWriteBps = uint64(float64(pi.IOWriteBytes-p.Write) / dt)
				}
				if pi.IOOtherBytes >= p.Other {
					pi.IOOtherBps = uint64(float64(pi.IOOtherBytes-p.Other) / dt)
				}
			}
		}

		next[pi.Pid] = sample
	}

	*prev = next
}
