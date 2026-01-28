package classifier

import (
	"sort"

	"proxywatch/internal/shared"
	"proxywatch/internal/telemetry"
)

// Classify converts a telemetry snapshot into classified candidates.
func Classify(
	snap *telemetry.Snapshot,
	minScore int,
	roleFilter map[string]bool,
) []shared.Candidate {

	candidates := buildCandidates(snap)

	var interesting []shared.Candidate
	for i := range candidates {
		ScoreCandidate(&candidates[i])

		if len(roleFilter) > 0 {
			if _, ok := roleFilter[candidates[i].Role]; !ok {
				continue
			}
		}

		if candidates[i].Score >= minScore || candidates[i].Role == "reverse-control" {
			interesting = append(interesting, candidates[i])
		}
	}

	sort.Slice(interesting, func(i, j int) bool {
		pri := rolePriority(interesting[i].Role)
		prj := rolePriority(interesting[j].Role)
		if pri != prj {
			return pri > prj
		}
		if interesting[i].ActiveProxying != interesting[j].ActiveProxying {
			return interesting[i].ActiveProxying && !interesting[j].ActiveProxying
		}
		if interesting[i].OutInternal != interesting[j].OutInternal {
			return interesting[i].OutInternal > interesting[j].OutInternal
		}
		if interesting[i].OutTotal != interesting[j].OutTotal {
			return interesting[i].OutTotal > interesting[j].OutTotal
		}
		if interesting[i].Score == interesting[j].Score {
			return interesting[i].Proc.Pid < interesting[j].Proc.Pid
		}
		return interesting[i].Score > interesting[j].Score
	})

	return interesting
}

func rolePriority(role string) int {
	switch role {
	case "reverse-transport":
		return 90
	case "reverse-proxy":
		return 80
	case "proxy-listener":
		return 70
	case "listener-with-clients":
		return 60
	case "listener-with-outbound":
		return 50
	case "reverse-control":
		return 40
	case "reverse-tunnel":
		return 35
	case "listener-only":
		return 30
	case "outbound-only":
		return 10
	case "no-network-activity":
		return 0
	default:
		return 0
	}
}

func buildCandidates(snap *telemetry.Snapshot) []shared.Candidate {
	lmap := make(map[int][]shared.ListenerInfo)
	for _, l := range snap.Listeners {
		lmap[l.Pid] = append(lmap[l.Pid], l)
	}

	cmap := make(map[int][]shared.ConnectionInfo)
	for _, c := range snap.Connections {
		cmap[c.Pid] = append(cmap[c.Pid], c)
	}

	seen := make(map[int]bool)
	for pid := range lmap {
		seen[pid] = true
	}
	for pid := range cmap {
		seen[pid] = true
	}

	var out []shared.Candidate
	for pid := range seen {
		proc := snap.Processes[pid]
		if proc == nil {
			continue
		}

		out = append(out, shared.Candidate{
			Proc:      proc,
			Listeners: lmap[pid],
			Conns:     cmap[pid],
		})
	}

	return out
}
