package shared

var InternalCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

var LateralPorts = map[int]bool{
	445:  true,
	3389: true,
	5985: true,
	5986: true,
	139:  true,
	389:  true,
	636:  true,
	1433: true,
	22:   true,
}
