package shared

import (
	"sync"
	"time"
)

type ProcessMeta struct {
	UserName    string
	ExePath     string
	Company     string
	Integrity   string
	SessionID   uint32
	SessionName string
	FetchedAt   time.Time
}

type ProcessMetaCache struct {
	mu      sync.Mutex
	entries map[int]ProcessMeta
}

func NewProcessMetaCache() *ProcessMetaCache {
	return &ProcessMetaCache{
		entries: make(map[int]ProcessMeta),
	}
}

func (c *ProcessMetaCache) Get(pid int, now time.Time) (ProcessMeta, bool) {
	if c == nil {
		return ProcessMeta{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	meta, ok := c.entries[pid]
	if !ok {
		return ProcessMeta{}, false
	}
	if now.Sub(meta.FetchedAt) > ProcessMetaCacheTTL {
		delete(c.entries, pid)
		return ProcessMeta{}, false
	}
	return meta, true
}

func (c *ProcessMetaCache) Set(pid int, meta ProcessMeta) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[pid] = meta
}

var ProcMetaCache = NewProcessMetaCache()
