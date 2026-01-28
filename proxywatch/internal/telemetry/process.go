//go:build windows
// +build windows

package telemetry

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"proxywatch/internal/shared"

	"golang.org/x/sys/windows"
)

var (
	modKernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessTimes      = modKernel32.NewProc("GetProcessTimes")
	procProcessIdToSessionId = modKernel32.NewProc("ProcessIdToSessionId")
	modPsapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = modPsapi.NewProc("GetProcessMemoryInfo")
)

type processMemoryCounters struct {
	Cb             uint32
	WorkingSetSize uintptr
}

func GetProcessInfoMap() (map[int]*shared.ProcessInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, err
	}

	procs := make(map[int]*shared.ProcessInfo)

	for {
		pid := int(entry.ProcessID)
		if pid != 0 {
			name := strings.ToLower(strings.TrimSpace(windows.UTF16ToString(entry.ExeFile[:])))

			pi := &shared.ProcessInfo{
				Pid:    pid,
				Name:   name,
				Status: "Running",
			}

			const access = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
			if h, err := windows.OpenProcess(access, false, uint32(pid)); err == nil {
				fillTimes(h, pi)
				fillMemory(h, pi)
				fillUser(h, pi)
				windows.CloseHandle(h)
			}

			fillSession(pi)
			procs[pid] = pi
		}

		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}

	return procs, nil
}

/* --- helpers --- */

func fillTimes(h windows.Handle, pi *shared.ProcessInfo) {
	var c, e, k, u windows.Filetime
	if r, _, _ := procGetProcessTimes.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&c)),
		uintptr(unsafe.Pointer(&e)),
		uintptr(unsafe.Pointer(&k)),
		uintptr(unsafe.Pointer(&u)),
	); r == 0 {
		return
	}

	pi.CpuTime = filetimeToDuration(k) + filetimeToDuration(u)
}

func fillMemory(h windows.Handle, pi *shared.ProcessInfo) {
	var pmc processMemoryCounters
	pmc.Cb = uint32(unsafe.Sizeof(pmc))

	if r, _, _ := procGetProcessMemoryInfo.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&pmc)),
		uintptr(pmc.Cb),
	); r != 0 {
		pi.MemUsage = uint64(pmc.WorkingSetSize)
	}
}

func fillSession(pi *shared.ProcessInfo) {
	var sid uint32
	if r, _, _ := procProcessIdToSessionId.Call(
		uintptr(uint32(pi.Pid)),
		uintptr(unsafe.Pointer(&sid)),
	); r != 0 {
		pi.SessionID = sid
		if sid == 0 {
			pi.SessionName = "Console"
		} else {
			pi.SessionName = fmt.Sprintf("Session-%d", sid)
		}
	}
}

func fillUser(h windows.Handle, pi *shared.ProcessInfo) {
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return
	}
	defer token.Close()

	tu, err := token.GetTokenUser()
	if err != nil || tu.User.Sid == nil {
		return
	}

	name, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return
	}

	if domain != "" {
		pi.UserName = domain + `\` + name
	} else {
		pi.UserName = name
	}
}

func filetimeToDuration(ft windows.Filetime) time.Duration {
	v := (uint64(ft.HighDateTime) << 32) | uint64(ft.LowDateTime)
	return time.Duration(v * 100)
}
