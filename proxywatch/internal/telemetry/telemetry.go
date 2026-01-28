//go:build windows
// +build windows

package telemetry

import (
	"fmt"
	"time"

	"proxywatch/internal/shared"
)

type Snapshot struct {
	Timestamp   time.Time
	Processes   map[int]*shared.ProcessInfo
	Listeners   []shared.ListenerInfo
	Connections []shared.ConnectionInfo
}

const (
	burstSamples = 5
	burstSleep   = 40 * time.Millisecond
)

func Collect() (*Snapshot, error) {
	listeners, conns, err := GetTCPTable()
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}

	if burstSamples > 1 {
		listeners, conns = burstCapture(listeners, conns)
	}

	procs, err := GetProcessInfoMap()
	if err != nil {
		return nil, fmt.Errorf("process: %w", err)
	}

	return &Snapshot{
		Timestamp:   time.Now().UTC(),
		Processes:   procs,
		Listeners:   listeners,
		Connections: conns,
	}, nil
}

type listenerKey struct {
	pid  int
	addr string
	port int
}

type connKey struct {
	pid        int
	localAddr  string
	localPort  int
	remoteAddr string
	remotePort int
}

func burstCapture(
	baseListeners []shared.ListenerInfo,
	baseConns []shared.ConnectionInfo,
) ([]shared.ListenerInfo, []shared.ConnectionInfo) {

	listenerMap := make(map[listenerKey]shared.ListenerInfo, len(baseListeners))
	connMap := make(map[connKey]shared.ConnectionInfo, len(baseConns))

	mergeListeners(listenerMap, baseListeners)
	mergeConns(connMap, baseConns)

	for i := 1; i < burstSamples; i++ {
		time.Sleep(burstSleep)
		listeners, conns, err := GetTCPTable()
		if err != nil {
			continue
		}
		mergeListeners(listenerMap, listeners)
		mergeConns(connMap, conns)
	}

	outListeners := make([]shared.ListenerInfo, 0, len(listenerMap))
	for _, l := range listenerMap {
		outListeners = append(outListeners, l)
	}

	outConns := make([]shared.ConnectionInfo, 0, len(connMap))
	for _, c := range connMap {
		outConns = append(outConns, c)
	}

	return outListeners, outConns
}

func mergeListeners(dest map[listenerKey]shared.ListenerInfo, in []shared.ListenerInfo) {
	for _, l := range in {
		key := listenerKey{
			pid:  l.Pid,
			addr: l.LocalAddress,
			port: l.LocalPort,
		}
		dest[key] = l
	}
}

func mergeConns(dest map[connKey]shared.ConnectionInfo, in []shared.ConnectionInfo) {
	for _, c := range in {
		key := connKey{
			pid:        c.Pid,
			localAddr:  c.LocalAddress,
			localPort:  c.LocalPort,
			remoteAddr: c.RemoteAddress,
			remotePort: c.RemotePort,
		}

		existing, ok := dest[key]
		if !ok {
			dest[key] = c
			continue
		}
		if existing.State != "ESTABLISHED" && c.State == "ESTABLISHED" {
			dest[key] = c
		}
	}
}
