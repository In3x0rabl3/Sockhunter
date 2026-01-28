//go:build !windows
// +build !windows

package telemetry

import (
	"errors"
	"time"

	"proxywatch/internal/shared"
)

type Snapshot struct {
	Timestamp   time.Time
	Processes   map[int]*shared.ProcessInfo
	Listeners   []shared.ListenerInfo
	Connections []shared.ConnectionInfo
}

func Collect() (*Snapshot, error) {
	return nil, errors.New("telemetry collection is only supported on Windows")
}

func KillProcess(pid int) error {
	return errors.New("process termination is only supported on Windows")
}
