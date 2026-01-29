package shared

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type LogSnapshot struct {
	CapturedAt time.Time   `json:"captured_at"`
	Snapshot   *Snapshot   `json:"snapshot"`
	Candidates []Candidate `json:"candidates"`
}

type JSONLogger struct {
	mu      sync.Mutex
	w       io.Writer
	closeFn func() error
	pretty  bool
	started bool
	first   bool
}

func NewJSONLogger(path string, pretty bool) (*JSONLogger, error) {
	if path == "" {
		return nil, nil
	}
	if path == "-" {
		return &JSONLogger{
			w:      os.Stdout,
			pretty: pretty,
			first:  true,
		}, nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}

	return &JSONLogger{
		w:       f,
		closeFn: f.Close,
		pretty:  pretty,
		first:   true,
	}, nil
}

func (l *JSONLogger) WriteSnapshot(snap *Snapshot, candidates []Candidate) error {
	if l == nil || l.w == nil {
		return nil
	}

	entry := LogSnapshot{
		CapturedAt: time.Now().UTC(),
		Snapshot:   snap,
		Candidates: candidates,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.started {
		if _, err := io.WriteString(l.w, "[\n"); err != nil {
			return err
		}
		l.started = true
	}

	if !l.first {
		if _, err := io.WriteString(l.w, ",\n"); err != nil {
			return err
		}
	}
	l.first = false

	var (
		out []byte
		err error
	)
	if l.pretty {
		out, err = json.MarshalIndent(entry, "  ", "  ")
	} else {
		out, err = json.Marshal(entry)
	}
	if err != nil {
		return err
	}

	if _, err := l.w.Write(out); err != nil {
		return err
	}
	if _, err := io.WriteString(l.w, "\n"); err != nil {
		return err
	}

	return nil
}

func (l *JSONLogger) Close() error {
	if l == nil || l.w == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.started {
		if _, err := io.WriteString(l.w, "]\n"); err != nil {
			return err
		}
		l.started = false
	}

	if l.closeFn != nil {
		return l.closeFn()
	}
	return nil
}
