package shared

import "time"

type Snapshot struct {
	Timestamp   time.Time
	Processes   map[int]*ProcessInfo
	Listeners   []ListenerInfo
	Connections []ConnectionInfo
}

type ListenerKey struct {
	Pid  int
	Addr string
	Port int
}

const (
	BurstSamples = 5
	BurstSleep   = 40 * time.Millisecond
)
