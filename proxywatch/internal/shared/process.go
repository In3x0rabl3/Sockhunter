package shared

import "time"

type ProcessInfo struct {
	Pid         int
	Name        string
	SessionID   uint32
	SessionName string

	MemUsage uint64 // bytes (WorkingSetSize)
	Status   string // e.g. "Running"

	UserName    string        // DOMAIN\User
	CpuTime     time.Duration // user + kernel
	WindowTitle string        // reserved
}
