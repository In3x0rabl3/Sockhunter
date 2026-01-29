package shared

import "time"

type ProcessInfo struct {
	Pid         int
	ParentPid   int
	Name        string
	SessionID   uint32
	SessionName string

	MemUsage uint64 // bytes (WorkingSetSize)
	Status   string // e.g. "Running"

	UserName     string // DOMAIN\User
	ExePath      string
	Company      string // file publisher/company (if available)
	Integrity    string
	IOReadBytes  uint64
	IOWriteBytes uint64
	IOOtherBytes uint64
	IOReadBps    uint64
	IOWriteBps   uint64
	IOOtherBps   uint64
	CpuTime      time.Duration // user + kernel
	WindowTitle  string        // reserved
}
