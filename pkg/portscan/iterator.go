package portscan

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
)

// PortIterator iterates over a range of ports
type PortIterator struct {
	ports []int
	index int
}

// NewPortIterator creates a new iterator from a string definition
// Supported formats: "80", "80,443", "100-200", "top-100", "full"
func NewPortIterator(portStr string) (*PortIterator, error) {
	ports := make([]int, 0)

	if portStr == "" {
		return nil, fmt.Errorf("empty port string")
	}

	// Handle special keywords
	if portStr == "top-100" {
		ports = getTop100Ports()
		return &PortIterator{ports: ports}, nil
	}

	if portStr == "full" || portStr == "all" {
		// Priority Scan Strategy:
		// 1. Scan Top 100 ports first (High Priority)
		// 2. Scan the rest (Low Priority)

		topPorts := getTop100Ports()
		topPortsMap := make(map[int]bool)
		for _, p := range topPorts {
			topPortsMap[p] = true
			ports = append(ports, p)
		}

		// Append remaining ports (1-65535)
		for i := 1; i <= 65535; i++ {
			if !topPortsMap[i] {
				ports = append(ports, i)
			}
		}

		return &PortIterator{ports: ports}, nil
	}

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 == nil && err2 == nil && start <= end {
				for i := start; i <= end; i++ {
					if isValidPort(i) {
						ports = append(ports, i)
					}
				}
			}
		} else {
			port, err := strconv.Atoi(part)
			if err == nil && isValidPort(port) {
				ports = append(ports, port)
			}
		}
	}

	// Remove duplicates
	ports = removeDuplicateInt(ports)

	return &PortIterator{ports: ports}, nil
}

func getTop100Ports() []int {
	return []int{
		80, 443, 8080, 8443, 22, 21, 23, 25, 53, 110, 143, 389, 445, 3389, 135, 139, 8000, 8081, 9090,
		3306, 5432, 6379, 27017, 1433, 1521, 2181, 9200, 11211, 5672, 5900, 5000, 8888, 2222, 2375,
		8008, 8009, 8090, 8161, 8181, 9000, 10000, 4567, 1234, 5001, 5002, 5003, 5004, 5005, 5006, 5007,
		5008, 5009, 5010, 7001, 7002, 7070, 7071, 7100, 7547, 8001, 8002, 8003, 8004, 8005, 8006, 8007,
		8010, 8020, 8030, 8040, 8050, 8060, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8091, 8092,
		8093, 8094, 8095, 8096, 8097, 8098, 8099, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94,
	}
}

func removeDuplicateInt(intSlice []int) []int {
	keys := make(map[int]bool)
	list := []int{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func isValidPort(p int) bool {
	return p > 0 && p <= 65535
}

func (pi *PortIterator) Next() (int, bool) {
	if pi.index >= len(pi.ports) {
		return 0, false
	}
	port := pi.ports[pi.index]
	pi.index++
	return port, true
}

func (pi *PortIterator) Reset() {
	pi.index = 0
}

func (pi *PortIterator) Total() int {
	return len(pi.ports)
}

// HostIterator iterates over a list of hosts/IPs
type HostIterator struct {
	hosts []string
	index int
}

func (hi *HostIterator) Reset() {
	hi.index = 0
}

// NewHostIterator creates a new iterator from a list of targets
func NewHostIterator(targets []string) *HostIterator {
	var expandedHosts []string
	for _, t := range targets {
		// CIDR expansion
		if strings.Contains(t, "/") {
			if strings.HasSuffix(t, "/8") {
				if ips := sampleSubnet8(t); len(ips) > 0 {
					expandedHosts = append(expandedHosts, ips...)
					continue
				}
			} else {
				if ips, err := ipRangeFromCIDR(t); err == nil {
					expandedHosts = append(expandedHosts, ips...)
					continue
				}
			}
		}
		// IP Range expansion (e.g. 192.168.1.1-192.168.1.10)
		if strings.Contains(t, "-") {
			if ips, err := ipRangeFromRange(t); err == nil {
				expandedHosts = append(expandedHosts, ips...)
				continue
			}
		}
		expandedHosts = append(expandedHosts, t)
	}

	// Remove duplicates
	expandedHosts = removeDuplicateStr(expandedHosts)

	return &HostIterator{hosts: expandedHosts}
}

func (hi *HostIterator) Next() (string, bool) {
	if hi.index >= len(hi.hosts) {
		return "", false
	}
	host := hi.hosts[hi.index]
	hi.index++
	return host, true
}

func (hi *HostIterator) Shuffle() {
	rand.Shuffle(len(hi.hosts), func(i, j int) {
		hi.hosts[i], hi.hosts[j] = hi.hosts[j], hi.hosts[i]
	})
	hi.index = 0
}

func (hi *HostIterator) GetHosts() []string {
	return hi.hosts
}

func (hi *HostIterator) Total() int {
	return len(hi.hosts)
}

func ipRangeFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// Remove network address and broadcast address
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ipRangeFromRange(rangeStr string) ([]string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format")
	}

	startIP := net.ParseIP(parts[0])
	endIP := net.ParseIP(parts[1])

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP in range")
	}

	var ips []string
	for ip := startIP; !ip.Equal(endIP); inc(ip) {
		ips = append(ips, ip.String())
	}
	ips = append(ips, endIP.String())

	return ips, nil
}

func removeDuplicateStr(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func sampleSubnet8(cidr string) []string {
	base := cidr[:len(cidr)-2]
	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return nil
	}
	first := parts[0]
	var res []string
	commonSeconds := []int{0, 1, 2, 10, 100, 200, 254}
	for _, s := range commonSeconds {
		for t := 0; t < 256; t += 10 {
			res = append(res, firstDot(first, s, t, 1))
			res = append(res, firstDot(first, s, t, 254))
			res = append(res, firstDot(first, s, t, 2+rand.IntN(252)))
		}
	}
	for s := 0; s < 256; s += 32 {
		for t := 0; t < 256; t += 32 {
			res = append(res, firstDot(first, s, t, 1))
			res = append(res, firstDot(first, s, t, 2+rand.IntN(252)))
		}
	}
	return res
}

func firstDot(a string, b, c, d int) string {
	return fmt.Sprintf("%s.%d.%d.%d", a, b, c, d)
}
