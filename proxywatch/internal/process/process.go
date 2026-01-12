//go:build windows
// +build windows

package process

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

type ProcessInfo struct {
	Pid  int
	Name string
}

func GetProcessInfoMap() (map[int]*ProcessInfo, error) {
	cmd := exec.Command("tasklist", "/V", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tasklist failed: %w", err)
	}

	r := csv.NewReader(bytes.NewReader(out))
	r.FieldsPerRecord = -1

	m := make(map[int]*ProcessInfo)

	for {
		record, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("csv parse error: %w", err)
		}
		if len(record) < 2 {
			continue
		}

		name := strings.ToLower(strings.TrimSpace(record[0]))
		pidStr := strings.TrimSpace(record[1])

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		pi := &ProcessInfo{
			Pid:  pid,
			Name: name,
		}
		m[pid] = pi
	}

	return m, nil
}
