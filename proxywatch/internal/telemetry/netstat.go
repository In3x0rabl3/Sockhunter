//go:build windows
// +build windows

package telemetry

import (
	"fmt"
	"net"
	"unsafe"

	"proxywatch/internal/shared"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcp = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	AF_INET                 = 2
	AF_INET6                = 23
	TCP_TABLE_OWNER_PID_ALL = 5
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCP6RowOwnerPID struct {
	State         uint32
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	OwningPID     uint32
}

func GetTCPTable() ([]shared.ListenerInfo, []shared.ConnectionInfo, error) {
	l4, c4, err := getTCPTableForFamily(AF_INET)
	if err != nil {
		return nil, nil, err
	}
	l6, c6, err := getTCPTableForFamily(AF_INET6)
	if err != nil {
		return l4, c4, nil
	}
	return append(l4, l6...), append(c4, c6...), nil
}

func getTCPTableForFamily(family uint32) ([]shared.ListenerInfo, []shared.ConnectionInfo, error) {
	var size uint32

	r0, _, _ := procGetExtendedTcp.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)

	const ERROR_INSUFFICIENT_BUFFER = 122
	if r0 != uintptr(ERROR_INSUFFICIENT_BUFFER) && r0 != 0 {
		return nil, nil, fmt.Errorf("GetExtendedTcpTable size query failed: %d", r0)
	}

	buf := make([]byte, size)
	r0, _, e1 := procGetExtendedTcp.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	if r0 != 0 {
		return nil, nil, fmt.Errorf("GetExtendedTcpTable failed: %v (code=%d)", e1, r0)
	}

	bufPtr := uintptr(unsafe.Pointer(&buf[0]))
	num := *(*uint32)(unsafe.Pointer(bufPtr))
	rowPtr := bufPtr + unsafe.Sizeof(num)

	var listeners []shared.ListenerInfo
	var conns []shared.ConnectionInfo

	if family == AF_INET {
		rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
		for i := uint32(0); i < num; i++ {
			row := (*mibTCPRowOwnerPID)(unsafe.Pointer(rowPtr + uintptr(i)*rowSize))
			parseV4(row, &listeners, &conns)
		}
	} else {
		rowSize := unsafe.Sizeof(mibTCP6RowOwnerPID{})
		for i := uint32(0); i < num; i++ {
			row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(rowPtr + uintptr(i)*rowSize))
			parseV6(row, &listeners, &conns)
		}
	}

	return listeners, conns, nil
}

func parseV4(r *mibTCPRowOwnerPID, l *[]shared.ListenerInfo, c *[]shared.ConnectionInfo) {
	state := tcpStateToString(r.State)
	lip := net.IPv4(byte(r.LocalAddr), byte(r.LocalAddr>>8), byte(r.LocalAddr>>16), byte(r.LocalAddr>>24)).String()
	rip := net.IPv4(byte(r.RemoteAddr), byte(r.RemoteAddr>>8), byte(r.RemoteAddr>>16), byte(r.RemoteAddr>>24)).String()

	lp := ntohs(r.LocalPort)
	rp := ntohs(r.RemotePort)

	if state == "LISTENING" {
		*l = append(*l, shared.ListenerInfo{
			Pid:          int(r.OwningPID),
			LocalAddress: lip,
			LocalPort:    lp,
			State:        state,
		})
	} else {
		*c = append(*c, shared.ConnectionInfo{
			Pid:           int(r.OwningPID),
			LocalAddress:  lip,
			LocalPort:     lp,
			RemoteAddress: rip,
			RemotePort:    rp,
			State:         state,
		})
	}
}

func parseV6(r *mibTCP6RowOwnerPID, l *[]shared.ListenerInfo, c *[]shared.ConnectionInfo) {
	lip := net.IP(r.LocalAddr[:]).String()
	rip := net.IP(r.RemoteAddr[:]).String()
	lp := ntohs(r.LocalPort)
	rp := ntohs(r.RemotePort)
	state := tcpStateToString(r.State)

	if state == "LISTENING" {
		*l = append(*l, shared.ListenerInfo{
			Pid:          int(r.OwningPID),
			LocalAddress: lip,
			LocalPort:    lp,
			State:        state,
		})
	} else {
		*c = append(*c, shared.ConnectionInfo{
			Pid:           int(r.OwningPID),
			LocalAddress:  lip,
			LocalPort:     lp,
			RemoteAddress: rip,
			RemotePort:    rp,
			State:         state,
		})
	}
}

func ntohs(p uint32) int {
	v := uint16(p)
	return int((v >> 8) | (v << 8))
}

func tcpStateToString(s uint32) string {
	switch s {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTENING"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RECEIVED"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT_1"
	case 7:
		return "FIN_WAIT_2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	default:
		return "UNKNOWN"
	}
}
