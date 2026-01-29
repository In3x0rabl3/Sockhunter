package shared

type Candidate struct {
	Proc      *ProcessInfo
	Listeners []ListenerInfo
	Conns     []ConnectionInfo

	// classifier-owned fields
	Score          int
	Reasons        []string
	Role           string
	ActiveProxying bool

	ControlChannel         *ConnectionInfo
	ControlDurationSeconds int

	OutTotal    int
	OutExternal int
	OutInternal int
	OutLoopback int

	InboundTotal int
}
