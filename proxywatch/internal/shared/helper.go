package shared

import "net"

func IsInternalIP(ip string) bool {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return false
	}
	for _, cidr := range InternalCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(netIP) {
			return true
		}
	}
	return false
}

func IsLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

func IsWildcardIP(ip string) bool {
	return ip == "0.0.0.0" || ip == "::"
}

func TrimName(name string, max int) string {
	if len(name) <= max {
		return name
	}
	if max <= 3 {
		return name[:max]
	}
	return name[:max-3] + "..."
}
