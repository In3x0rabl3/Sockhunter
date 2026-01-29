package shared

import "time"

type Snapshot struct {
	Timestamp    time.Time
	Processes    map[int]*ProcessInfo
	Listeners    []ListenerInfo
	Connections  []ConnectionInfo
	UDPListeners []UDPListenerInfo
}

type ListenerKey struct {
	Pid  int
	Addr string
	Port int
}

const (
	BurstSamplesMax = 5
	BurstSamplesMid = 3
	BurstSamplesMin = 1
	BurstSleep      = 40 * time.Millisecond

	BurstIdleConnThreshold     = 5
	BurstModerateConnThreshold = 25

	ProcessMetaCacheTTL = 60 * time.Second
)
