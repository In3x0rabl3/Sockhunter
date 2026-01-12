//go:build windows
// +build windows

package netstat

import (
	"fmt"
	"net"
	"unsafe"

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

type ListenerInfo struct {
	Pid          int
	LocalAddress string
	LocalPort    int
	State        string
}

type ConnectionInfo struct {
	Pid           int
	LocalAddress  string
	LocalPort     int
	RemoteAddress string
	RemotePort    int
	State         string
}

func ipv4FromDWORD(addr uint32) string {
	b := []byte{
		byte(addr),
		byte(addr >> 8),
		byte(addr >> 16),
		byte(addr >> 24),
	}
	return net.IP(b).String()
}

func ntohs(p uint32) int {
	v := uint16(p)
	return int((v >> 8) | (v << 8))
}

func tcpStateToString(s uint32) string {
	switch s {
	case 2:
		return "LISTENING"
	case 5:
		return "ESTABLISHED"
	default:
		return "OTHER"
	}
}

func getTCPTableForFamily(family uint32) ([]ListenerInfo, []ConnectionInfo, error) {
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
	if size == 0 {
		return nil, nil, fmt.Errorf("GetExtendedTcpTable returned size 0")
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
	numEntries := *(*uint32)(unsafe.Pointer(bufPtr))
	firstRowPtr := bufPtr + unsafe.Sizeof(numEntries)

	var listeners []ListenerInfo
	var conns []ConnectionInfo

	if family == AF_INET {
		rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
		for i := uint32(0); i < numEntries; i++ {
			rowPtr := firstRowPtr + uintptr(i)*rowSize
			row := (*mibTCPRowOwnerPID)(unsafe.Pointer(rowPtr))

			pid := int(row.OwningPID)
			lIP := ipv4FromDWORD(row.LocalAddr)
			rIP := ipv4FromDWORD(row.RemoteAddr)
			lPort := ntohs(row.LocalPort)
			rPort := ntohs(row.RemotePort)
			state := tcpStateToString(row.State)

			if state == "LISTENING" {
				listeners = append(listeners, ListenerInfo{
					Pid:          pid,
					LocalAddress: lIP,
					LocalPort:    lPort,
					State:        state,
				})
			} else {
				conns = append(conns, ConnectionInfo{
					Pid:           pid,
					LocalAddress:  lIP,
					LocalPort:     lPort,
					RemoteAddress: rIP,
					RemotePort:    rPort,
					State:         state,
				})
			}
		}
	} else if family == AF_INET6 {
		rowSize := unsafe.Sizeof(mibTCP6RowOwnerPID{})
		for i := uint32(0); i < numEntries; i++ {
			rowPtr := firstRowPtr + uintptr(i)*rowSize
			row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(rowPtr))

			pid := int(row.OwningPID)
			lIP := net.IP(row.LocalAddr[:]).String()
			rIP := net.IP(row.RemoteAddr[:]).String()
			lPort := ntohs(row.LocalPort)
			rPort := ntohs(row.RemotePort)
			state := tcpStateToString(row.State)

			if state == "LISTENING" {
				listeners = append(listeners, ListenerInfo{
					Pid:          pid,
					LocalAddress: lIP,
					LocalPort:    lPort,
					State:        state,
				})
			} else {
				conns = append(conns, ConnectionInfo{
					Pid:           pid,
					LocalAddress:  lIP,
					LocalPort:     lPort,
					RemoteAddress: rIP,
					RemotePort:    rPort,
					State:         state,
				})
			}
		}
	}

	return listeners, conns, nil
}

func GetTCPTable() ([]ListenerInfo, []ConnectionInfo, error) {
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
