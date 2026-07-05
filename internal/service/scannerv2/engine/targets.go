package engine

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// parseScanTargets expands a target spec into a list of IP strings.
// Supported formats (single or comma-separated):
//   - CIDR: "192.168.1.0/24"
//   - single IP: "192.168.1.5"
//   - IP range: "192.168.1.1-192.168.1.10" or "192.168.1.1-10"
//
// Ported from the legacy scanner so the v2 engine supports the same target
// syntax users already know. Errors are descriptive for the API layer to map
// to HTTP 400.
func parseScanTargets(targets string) ([]string, error) {
	targets = strings.TrimSpace(targets)
	if targets == "" {
		return nil, fmt.Errorf("targets is empty")
	}

	// Comma-separated list of any of the above.
	if strings.Contains(targets, ",") {
		var ips []string
		for _, part := range strings.Split(targets, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			expanded, err := parseSingleTarget(part)
			if err != nil {
				return nil, err
			}
			ips = append(ips, expanded...)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no valid targets")
		}
		return ips, nil
	}

	return parseSingleTarget(targets)
}

func parseSingleTarget(t string) ([]string, error) {
	// CIDR.
	if _, ipNet, err := net.ParseCIDR(t); err == nil && ipNet != nil {
		return enumerateCIDR(ipNet), nil
	}
	// Single IP.
	if ip := net.ParseIP(t); ip != nil {
		return []string{ip.String()}, nil
	}
	// Range "a.b.c.d-a.b.c.e" or "a.b.c.d-e".
	if strings.Contains(t, "-") {
		return parseIPRange(t)
	}
	return nil, fmt.Errorf("invalid target: %s", t)
}

func enumerateCIDR(ipNet *net.IPNet) []string {
	ones, bits := ipNet.Mask.Size()
	if ones == bits {
		return []string{ipNet.IP.String()}
	}
	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

func parseIPRange(s string) ([]string, error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range: %s", s)
	}
	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])
	startIP := net.ParseIP(startStr)
	if startIP == nil {
		return nil, fmt.Errorf("invalid range start: %s", startStr)
	}
	start4 := startIP.To4()
	if start4 == nil {
		return nil, fmt.Errorf("IPv6 ranges unsupported: %s", s)
	}

	var end4 net.IP
	// Full end IP.
	if e := net.ParseIP(endStr); e != nil {
		end4 = e.To4()
	} else {
		// Suffix range: "192.168.1.1-10" → replace last octet.
		n, err := strconv.Atoi(endStr)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("invalid range end: %s", endStr)
		}
		end4 = append(net.IP{}, start4...)
		end4[3] = byte(n)
	}
	if end4 == nil {
		return nil, fmt.Errorf("invalid range end: %s", endStr)
	}

	// Ensure start <= end by comparing the full 32-bit value. The previous code
	// only compared the last octet (a /24 assumption), which produced wrong /
	// empty results for cross-boundary ranges like "192.168.1.200-192.168.2.10".
	startU := uint32(start4[0])<<24 | uint32(start4[1])<<16 | uint32(start4[2])<<8 | uint32(start4[3])
	endU := uint32(end4[0])<<24 | uint32(end4[1])<<16 | uint32(end4[2])<<8 | uint32(end4[3])
	if startU > endU {
		start4, end4 = end4, start4
		startU, endU = endU, startU
	}

	// Cap the range size to protect against accidental huge ranges (e.g.
	// "10.0.0.0-10.255.255.255"). 65536 covers any realistic /16-equivalent
	// range; larger needs should use CIDR + the async task API. The previous
	// code silently truncated at 1000 IPs with no error — now we fail loudly.
	const maxRangeIPs = 65536
	count := int(endU-startU) + 1
	if count > maxRangeIPs {
		return nil, fmt.Errorf("range too large: %d IPs (max %d); use a CIDR with the async task API", count, maxRangeIPs)
	}

	ips := make([]string, 0, count)
	cur := append(net.IP{}, start4...)
	curU := startU
	for curU <= endU {
		ips = append(ips, net.IP(append(net.IP{}, cur...)).String())
		if curU == endU {
			break
		}
		incIP(cur)
		curU = uint32(cur[0])<<24 | uint32(cur[1])<<16 | uint32(cur[2])<<8 | uint32(cur[3])
	}
	return ips, nil
}

// incIP mutates ip in place to the next IP address.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
