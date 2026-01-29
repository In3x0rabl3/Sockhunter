//go:build windows
// +build windows

package telemetry

import (
	"fmt"
	"net"
	"unsafe"

	"proxywatch/internal/shared"
)

func GetUDPTable() ([]shared.UDPListenerInfo, error) {
	l4, err := getUDPTableForFamily(shared.AF_INET)
	if err != nil {
		return nil, err
	}
	l6, err := getUDPTableForFamily(shared.AF_INET6)
	if err != nil {
		return l4, nil
	}
	return append(l4, l6...), nil
}

func getUDPTableForFamily(family uint32) ([]shared.UDPListenerInfo, error) {
	var size uint32

	r0, _, _ := shared.ProcGetExtendedUdp.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(shared.UDP_TABLE_OWNER_PID),
		0,
	)

	const ERROR_INSUFFICIENT_BUFFER = 122
	if r0 != uintptr(ERROR_INSUFFICIENT_BUFFER) && r0 != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable size query failed: %d", r0)
	}

	buf := make([]byte, size)
	r0, _, e1 := shared.ProcGetExtendedUdp.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(shared.UDP_TABLE_OWNER_PID),
		0,
	)
	if r0 != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %v (code=%d)", e1, r0)
	}

	bufPtr := uintptr(unsafe.Pointer(&buf[0]))
	num := *(*uint32)(unsafe.Pointer(bufPtr))
	rowPtr := bufPtr + unsafe.Sizeof(num)

	out := make([]shared.UDPListenerInfo, 0, num)

	if family == shared.AF_INET {
		rowSize := unsafe.Sizeof(shared.MIBUDPROwnerPID{})
		for i := uint32(0); i < num; i++ {
			row := (*shared.MIBUDPROwnerPID)(unsafe.Pointer(rowPtr + uintptr(i)*rowSize))
			out = append(out, parseUDPv4(row))
		}
	} else {
		rowSize := unsafe.Sizeof(shared.MIBUDP6OwnerPID{})
		for i := uint32(0); i < num; i++ {
			row := (*shared.MIBUDP6OwnerPID)(unsafe.Pointer(rowPtr + uintptr(i)*rowSize))
			out = append(out, parseUDPv6(row))
		}
	}

	return out, nil
}

func parseUDPv4(r *shared.MIBUDPROwnerPID) shared.UDPListenerInfo {
	lip := net.IPv4(byte(r.LocalAddr), byte(r.LocalAddr>>8), byte(r.LocalAddr>>16), byte(r.LocalAddr>>24)).String()
	lp := ntohs(r.LocalPort)
	return shared.UDPListenerInfo{
		Pid:          int(r.OwningPID),
		LocalAddress: lip,
		LocalPort:    lp,
	}
}

func parseUDPv6(r *shared.MIBUDP6OwnerPID) shared.UDPListenerInfo {
	lip := net.IP(r.LocalAddr[:]).String()
	lp := ntohs(r.LocalPort)
	return shared.UDPListenerInfo{
		Pid:          int(r.OwningPID),
		LocalAddress: lip,
		LocalPort:    lp,
	}
}
