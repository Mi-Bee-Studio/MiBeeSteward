// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package cidrutil provides shared CIDR-membership helpers used to enforce the
// network-boundary invariant: a device/scan target may only be attributed to the
// network whose CIDR actually contains its IP. See issue #19.
//
// It exists as a leaf package (no deps on internal/) so the agent command
// channel, the agent-report ingestion handler, and the background reconciliation
// job can all share one canonical implementation without risking an import cycle
// (those packages already pull in the runner / engine).
package cidrutil

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ErrEmptyCIDR is returned by ParseNetwork when the input is blank. Callers use
// it to distinguish "no CIDR configured (skip validation)" from "CIDR invalid
// (reject)" — the two warrant different handling in the command/report paths.
var ErrEmptyCIDR = errors.New("cidrutil: cidr is empty")

// ParseNetwork parses a CIDR string (e.g. "192.168.63.0/24") into an IPNet.
// Returns (nil, ErrEmptyCIDR) for an empty/whitespace-only string so callers can
// treat a missing CIDR as "validation disabled" rather than a hard error. Any
// other parse failure returns the underlying error.
func ParseNetwork(cidr string) (*net.IPNet, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil, ErrEmptyCIDR
	}
	// net.ParseCIDR requires the "/prefix" form. A bare IP like "192.168.63.1"
	// is a valid single-host network — accept it as /32 (v4) / /128 (v6) so the
	// helpers work uniformly for both CIDR and single-IP network definitions.
	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("cidrutil: invalid network %q: not a CIDR or IP", cidr)
		}
		if ip.To4() != nil {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("cidrutil: invalid cidr %q: %w", cidr, err)
	}
	return ipNet, nil
}

// ContainsIP reports whether ipStr falls inside network. A nil/empty network or
// an unparseable ipStr returns false — never panics. Callers that need to
// distinguish "no network configured" from "ip out of range" should check the
// network via ParseNetwork first (see MustContain / the report-handler usage).
func ContainsIP(network *net.IPNet, ipStr string) bool {
	if network == nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	return network.Contains(ip)
}

// PartitionTargets expands a target spec (CIDR / single IP / range, single or
// comma-separated — the same syntax the scan engine accepts) and partitions the
// resulting IPs into (in, out): those inside vs outside the given network. This
// is what the agent-command and agent-report paths use to reject or quarantine
// out-of-network targets.
//
// Returns an error only if the target spec itself is unparseable (mirrors the
// engine's parseScanTargets semantics). A nil network yields (nil, nil, nil) —
// callers that want strict mode should guard with ParseNetwork first.
func PartitionTargets(targets string, network *net.IPNet) (in, out []string, err error) {
	if network == nil {
		return nil, nil, nil
	}
	ips, err := expandTargets(targets)
	if err != nil {
		return nil, nil, err
	}
	for _, ip := range ips {
		if network.Contains(net.ParseIP(ip)) {
			in = append(in, ip)
		} else {
			out = append(out, ip)
		}
	}
	return in, out, nil
}

// expandTargets mirrors engine.parseScanTargets but lives here so this package
// stays a leaf (the engine package pulls in heavier deps). Kept in sync by the
// shared test in cidrutil_test.go that asserts parity with the engine for a set
// of representative inputs.
func expandTargets(targets string) ([]string, error) {
	targets = strings.TrimSpace(targets)
	if targets == "" {
		return nil, fmt.Errorf("targets is empty")
	}
	if strings.Contains(targets, ",") {
		var ips []string
		for _, part := range strings.Split(targets, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			expanded, err := expandSingle(part)
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
	return expandSingle(targets)
}

func expandSingle(t string) ([]string, error) {
	if _, ipNet, err := net.ParseCIDR(t); err == nil && ipNet != nil {
		return enumerateCIDR(ipNet), nil
	}
	if ip := net.ParseIP(t); ip != nil {
		return []string{ip.String()}, nil
	}
	if strings.Contains(t, "-") {
		return expandIPRange(t)
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
	if skipFirst, skipLast := v4ReservedBounds(ipNet); skipFirst {
		ips = ips[1:]
		if skipLast && len(ips) > 0 {
			ips = ips[:len(ips)-1]
		}
	}
	return ips
}

// v4ReservedBounds mirrors engine.v4ReservedBounds (kept in sync by the parity
// test): IPv4 networks wider than /31 exclude the network + broadcast
// addresses — the broadcast IP answers pings via every host's reply and gets
// recorded as a phantom device (#254). /31 (RFC 3021), /32, and IPv6 exclude
// nothing.
func v4ReservedBounds(ipNet *net.IPNet) (skipFirst, skipLast bool) {
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones >= 31 {
		return false, false
	}
	return true, true
}

func expandIPRange(s string) ([]string, error) {
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
	if e := net.ParseIP(endStr); e != nil {
		end4 = e.To4()
	} else {
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
	startU := uint32(start4[0])<<24 | uint32(start4[1])<<16 | uint32(start4[2])<<8 | uint32(start4[3])
	endU := uint32(end4[0])<<24 | uint32(end4[1])<<16 | uint32(end4[2])<<8 | uint32(end4[3])
	if startU > endU {
		start4 = end4
		startU, endU = endU, startU
	}
	const maxRangeIPs = 65536
	count := int(endU-startU) + 1
	if count > maxRangeIPs {
		return nil, fmt.Errorf("range too large: %d IPs (max %d)", count, maxRangeIPs)
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

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
