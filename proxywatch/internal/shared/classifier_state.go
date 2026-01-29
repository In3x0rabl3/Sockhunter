package shared

import "time"

type ConnKey struct {
	Pid        int
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
}

type ProcHistory struct {
	LastSeen       time.Time
	LastActive     time.Time
	LastSuspicious time.Time
	SuspicionKind  int
	StickyScore    int
}

const (
	SuspicionNone = iota
	SuspicionControl
	SuspicionProxy
)

var (
	ConnFirstSeen             = make(map[ConnKey]time.Time)
	ReverseControlMinDuration = 10 * time.Second
	LongLivedOutboundMinAge   = 60 * time.Second
	ShortLivedOutboundMaxAge  = 10 * time.Second
	RecentClientSeen          = make(map[int]time.Time)
	RecentOutboundSeen        = make(map[int]time.Time)
	ActiveWindow              = 10 * time.Second
	ActiveHoldWindow          = 30 * time.Second
	SuspicionWindow           = 5 * time.Minute
	HistoryTTL                = 5 * time.Minute
	CleanupInterval           = 30 * time.Second
	ReverseStickyScore        = 90
	ForwardStickyScore        = 70
	ReverseControlBaseScore   = 40
	MinInternalTargetsForRev  = 2
	MinInternalPortsForRev    = 2
	OutboundOnlyExternalCap   = 30
	ProcHistoryByPID          = make(map[int]*ProcHistory)
	LastHistoryCleanup        time.Time
	BenignControlPorts        = map[int]bool{
		53:   true,
		80:   true,
		443:  true,
		8080: true,
		8443: true,
		8000: true,
		8001: true,
		8008: true,
		8888: true,
	}
)
