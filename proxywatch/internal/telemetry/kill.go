//go:build windows
// +build windows

package telemetry

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// KillProcess terminates the process with the given PID.
func KillProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}

	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("open process: %w", err)
	}
	defer windows.CloseHandle(h)

	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("terminate process: %w", err)
	}

	return nil
}
