//go:build windows
// +build windows

package process

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ProcessInfo struct {
	Pid         int
	Name        string
	SessionID   uint32
	SessionName string

	MemUsage uint64 // bytes (WorkingSetSize)
	Status   string // e.g. "Running"

	UserName    string        // DOMAIN\User
	CpuTime     time.Duration // user + kernel
	WindowTitle string        // left empty in this version
}

// --- Win32 / native bindings ---

var (
	modKernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessTimes         = modKernel32.NewProc("GetProcessTimes")
	procProcessIdToSessionId    = modKernel32.NewProc("ProcessIdToSessionId")
	modPsapi                    = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo    = modPsapi.NewProc("GetProcessMemoryInfo")
)

// PROCESS_MEMORY_COUNTERS from psapi.h
type processMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// filetimeToDuration converts a Windows FILETIME (100 ns intervals) to time.Duration.
func filetimeToDuration(ft windows.Filetime) time.Duration {
	v := (uint64(ft.HighDateTime) << 32) | uint64(ft.LowDateTime)
	// 1 tick = 100 ns
	return time.Duration(v * 100)
}

// fillProcessTimes populates CpuTime (user + kernel).
func fillProcessTimes(h windows.Handle, pi *ProcessInfo) {
	var create, exit, kernelTime, userTime windows.Filetime

	r1, _, _ := procGetProcessTimes.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&create)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	if r1 == 0 {
		return // best-effort; ignore failure
	}

	kt := filetimeToDuration(kernelTime)
	ut := filetimeToDuration(userTime)
	pi.CpuTime = kt + ut
}

// fillProcessMemory populates MemUsage from WorkingSetSize.
func fillProcessMemory(h windows.Handle, pi *ProcessInfo) {
	var pmc processMemoryCounters
	pmc.Cb = uint32(unsafe.Sizeof(pmc))

	r1, _, _ := procGetProcessMemoryInfo.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&pmc)),
		uintptr(pmc.Cb),
	)
	if r1 == 0 {
		return // best-effort
	}

	pi.MemUsage = uint64(pmc.WorkingSetSize)
}

// fillProcessSession populates SessionID + a simple SessionName.
func fillProcessSession(pi *ProcessInfo) {
	var sid uint32
	r1, _, _ := procProcessIdToSessionId.Call(
		uintptr(uint32(pi.Pid)),
		uintptr(unsafe.Pointer(&sid)),
	)
	if r1 == 0 {
		return // best-effort
	}
	pi.SessionID = sid

	// Tasklist's "Session Name" is more nuanced (WTS APIs). For now:
	if sid == 0 {
		pi.SessionName = "Console"
	} else {
		pi.SessionName = fmt.Sprintf("Session-%d", sid)
	}
}

// fillProcessUser populates UserName (DOMAIN\User) if possible.
func fillProcessUser(h windows.Handle, pi *ProcessInfo) {
	var token windows.Token
	// TOKEN_QUERY is enough to get TokenUser
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return
	}
	defer token.Close()

	tu, err := token.GetTokenUser()
	if err != nil {
		return
	}

	sid := tu.User.Sid
	if sid == nil {
		return
	}

	name, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return
	}

	if domain != "" {
		pi.UserName = domain + `\` + name
	} else {
		pi.UserName = name
	}
}

// GetProcessInfoMap enumerates processes via Toolhelp32 + Win32 APIs,
// approximating tasklist /V /FO CSV but without spawning a process.
func GetProcessInfoMap() (map[int]*ProcessInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, fmt.Errorf("Process32First failed: %w", err)
	}

	m := make(map[int]*ProcessInfo)

	for {
		pid := int(entry.ProcessID)
		if pid != 0 { // skip the System Idle Process, etc., if desired
			name := windows.UTF16ToString(entry.ExeFile[:])
			name = strings.ToLower(strings.TrimSpace(name))

			pi := &ProcessInfo{
				Pid:   pid,
				Name:  name,
				Status: "Running", // baseline; you can refine if you want "Not Responding" semantics
			}

			// Best-effort: open process and collect extra info
			// Use fairly standard rights; this will fail for some protected processes.
			const desiredAccess = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
			h, err := windows.OpenProcess(desiredAccess, false, uint32(pid))
			if err == nil {
				fillProcessTimes(h, pi)
				fillProcessMemory(h, pi)
				fillProcessUser(h, pi)
				windows.CloseHandle(h)
			}

			fillProcessSession(pi)

			m[pid] = pi
		}

		err := windows.Process32Next(snap, &entry)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return nil, fmt.Errorf("Process32Next failed: %w", err)
		}
	}

	return m, nil
}
