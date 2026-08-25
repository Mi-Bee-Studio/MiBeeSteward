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

// Sentinel errors for target parsing/expansion. The engine aliases these
// (its parseScanTargets delegates here), and the API layer classifies them via
// errors.Is to map user-supplied-bad-targets to HTTP 400 instead of brittle
// string matching on error text.
var (
	ErrEmptyTargets         = errors.New("targets is empty")
	ErrNoValidTargets       = errors.New("no valid targets")
	ErrInvalidTarget        = errors.New("invalid target")
	ErrInvalidIPRange       = errors.New("invalid IP range")
	ErrIPv6RangeUnsupported = errors.New("IPv6 ranges unsupported")
	ErrTargetRangeTooLarge  = errors.New("target range too large")
	// ErrReservedTarget marks a target spec pointing at reserved/non-routable
	// address space (loopback, unspecified, link-local, multicast, limited
	// broadcast, 240/4). Such targets never yield a real LAN device: Linux
	// answers the whole 127/8 from loopback, so scanning it invents thousands
	// of phantom devices (#317), and broadcast/multicast addresses are
	// shared-medium identities, not hosts (#254).
	ErrReservedTarget = errors.New("target in reserved address space")
)

// reservedClass names the reserved/non-routable class an IP belongs to, or ""
// for an ordinary (private or public) unicast address.
func reservedClass(ip net.IP) string {
	if ip == nil {
		return ""
	}
	switch {
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast():
		return "link-local unicast"
	case ip.IsMulticast():
		return "multicast"
	case ip.Equal(net.IPv4bcast):
		return "limited broadcast"
	}
	if v4 := ip.To4(); v4 != nil && v4[0] >= 240 {
		return "reserved (240.0.0.0/4)"
	}
	return ""
}

// lastAddress returns the highest address of ipNet (its directed broadcast for
// IPv4), or nil for a single-host prefix.
func lastAddress(ipNet *net.IPNet) net.IP {
	ones, bits := ipNet.Mask.Size()
	if ones >= bits {
		return nil
	}
	last := append(net.IP{}, ipNet.IP...)
	for i := range last {
		last[i] |= ^ipNet.Mask[i]
	}
	return last
}

// checkReserved rejects a target part classified by its first and last
// addresses. Checking both endpoints also catches blocks that merely overlap
// reserved space (e.g. 126.0.0.0/7, whose upper half is the 127/8 loopback).
func checkReserved(part string, first, last net.IP) error {
	if class := reservedClass(first); class != "" {
		return fmt.Errorf("%w: %s is %s", ErrReservedTarget, part, class)
	}
	if last != nil {
		if class := reservedClass(last); class != "" {
			return fmt.Errorf("%w: %s overlaps %s (ends at %s)", ErrReservedTarget, part, class, last)
		}
	}
	return nil
}

// ValidateTargets rejects a target spec (CIDR / single IP / range, single or
// comma-separated — the same syntax the scan engine accepts) whose parts fall
// wholly or partly into reserved address space. It inspects each part's
// endpoints only, so validating a huge CIDR never expands it. Private
// (RFC1918) space is NOT rejected — it is the product's bread and butter.
// All scan entry points (task create/update, synchronous scan, agent command
// enqueue) call this before accepting targets (#317).
func ValidateTargets(targets string) error {
	return ValidateTargetsFor(targets, false)
}

// ValidateTargetsFor is the flag-aware form of ValidateTargets. With
// allowReserved=true (the scanner.allow_reserved_targets escape hatch, used by
// the synthetic loadgen plane on 127/8) reserved ranges are accepted; the
// syntax of every part is still validated either way.
func ValidateTargetsFor(targets string, allowReserved bool) error {
	targets = strings.TrimSpace(targets)
	if targets == "" {
		return ErrEmptyTargets
	}
	for _, part := range strings.Split(targets, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(part); err == nil && ipNet != nil {
			if !allowReserved {
				if err := checkReserved(part, ipNet.IP, lastAddress(ipNet)); err != nil {
					return err
				}
			}
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			if !allowReserved {
				if class := reservedClass(ip); class != "" {
					return fmt.Errorf("%w: %s is %s", ErrReservedTarget, part, class)
				}
			}
			continue
		}
		if strings.Contains(part, "-") {
			start, end, err := rangeBounds(part)
			if err != nil {
				return err
			}
			if !allowReserved {
				if err := checkReserved(part, start, end); err != nil {
					return err
				}
			}
			continue
		}
		return fmt.Errorf("%w: %s", ErrInvalidTarget, part)
	}
	return nil
}

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
// Returns an error if the target spec itself is unparseable or points at
// reserved address space (mirrors the engine's parseScanTargets semantics,
// which now delegates to the same expansion). A nil network yields
// (nil, nil, nil) — callers that want strict mode should guard with
// ParseNetwork first.
func PartitionTargets(targets string, network *net.IPNet) (in, out []string, err error) {
	if network == nil {
		return nil, nil, nil
	}
	ips, err := ExpandTargets(targets)
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

// ExpandTargets expands a target spec into the list of IP strings the engine
// will scan. It is the single canonical expansion implementation: the engine's
// parseScanTargets delegates here (no more mirrored copies to keep in sync).
// Specs pointing at reserved address space are rejected with ErrReservedTarget.
func ExpandTargets(targets string) ([]string, error) {
	return ExpandTargetsFor(targets, false)
}

// ExpandTargetsFor is the flag-aware form of ExpandTargets (see
// ValidateTargetsFor for the escape-hatch semantics).
func ExpandTargetsFor(targets string, allowReserved bool) ([]string, error) {
	targets = strings.TrimSpace(targets)
	if targets == "" {
		return nil, ErrEmptyTargets
	}
	if strings.Contains(targets, ",") {
		var ips []string
		for _, part := range strings.Split(targets, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			expanded, err := expandSingle(part, allowReserved)
			if err != nil {
				return nil, err
			}
			ips = append(ips, expanded...)
		}
		if len(ips) == 0 {
			return nil, ErrNoValidTargets
		}
		return ips, nil
	}
	return expandSingle(targets, allowReserved)
}

func expandSingle(t string, allowReserved bool) ([]string, error) {
	if _, ipNet, err := net.ParseCIDR(t); err == nil && ipNet != nil {
		if !allowReserved {
			if err := checkReserved(t, ipNet.IP, lastAddress(ipNet)); err != nil {
				return nil, err
			}
		}
		return enumerateCIDR(ipNet), nil
	}
	if ip := net.ParseIP(t); ip != nil {
		if !allowReserved {
			if class := reservedClass(ip); class != "" {
				return nil, fmt.Errorf("%w: %s is %s", ErrReservedTarget, t, class)
			}
		}
		return []string{ip.String()}, nil
	}
	if strings.Contains(t, "-") {
		start, end, err := rangeBounds(t)
		if err != nil {
			return nil, err
		}
		if !allowReserved {
			if err := checkReserved(t, start, end); err != nil {
				return nil, err
			}
		}
		return enumerateRange(start, end)
	}
	return nil, fmt.Errorf("%w: %s", ErrInvalidTarget, t)
}

// enumerateCIDR lists the HOST addresses of a block. For IPv4 prefixes up to
// /30 the network (first) and directed-broadcast (last) addresses are dropped:
// they belong to the medium, not to any host — nmap semantics. This stops
// subnet scans from inventing .0/.255 "devices" (#254). /31 point-to-point
// links use both addresses (RFC 3021) and /32 is a single host, so neither is
// trimmed. IPv6 has no broadcast concept.
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

// v4ReservedBounds reports whether an IPv4 network's expansion should drop its
// network (first) and directed-broadcast (last) addresses: wider than /31 they
// belong to the medium, not to any host — the broadcast IP answers pings via
// every host's reply and gets recorded as a phantom device (#254). /31
// (RFC 3021 point-to-point), /32, and IPv6 exclude nothing. This is the single
// canonical implementation; the engine's target parser delegates here.
func v4ReservedBounds(ipNet *net.IPNet) (skipFirst, skipLast bool) {
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones >= 31 {
		return false, false
	}
	return true, true
}

// rangeBounds parses "a.b.c.d-a.b.c.e" or "a.b.c.d-e" (suffix replaces the
// last octet) into its IPv4 endpoints, swapping if given in reverse order.
// Shared by ValidateTargetsFor (endpoint classification) and expandSingle
// (enumeration) so the two can't drift on range syntax.
func rangeBounds(s string) (start, end net.IP, err error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("%w: %s", ErrInvalidIPRange, s)
	}
	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])
	startIP := net.ParseIP(startStr)
	if startIP == nil {
		return nil, nil, fmt.Errorf("%w: invalid range start %s", ErrInvalidIPRange, startStr)
	}
	start4 := startIP.To4()
	if start4 == nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrIPv6RangeUnsupported, s)
	}

	var end4 net.IP
	if e := net.ParseIP(endStr); e != nil {
		end4 = e.To4()
	} else {
		n, aerr := strconv.Atoi(endStr)
		if aerr != nil || n < 0 || n > 255 {
			return nil, nil, fmt.Errorf("%w: invalid range end %s", ErrInvalidIPRange, endStr)
		}
		end4 = append(net.IP{}, start4...)
		end4[3] = byte(n)
	}
	if end4 == nil {
		return nil, nil, fmt.Errorf("%w: invalid range end %s", ErrInvalidIPRange, endStr)
	}

	startU := uint32(start4[0])<<24 | uint32(start4[1])<<16 | uint32(start4[2])<<8 | uint32(start4[3])
	endU := uint32(end4[0])<<24 | uint32(end4[1])<<16 | uint32(end4[2])<<8 | uint32(end4[3])
	if startU > endU {
		start4, end4 = end4, start4
	}
	return start4, end4, nil
}

// enumerateRange lists every IPv4 address from start to end inclusive.
func enumerateRange(start, end net.IP) ([]string, error) {
	start4 := start.To4()
	end4 := end.To4()
	if start4 == nil || end4 == nil {
		return nil, fmt.Errorf("%w: non-IPv4 range endpoints", ErrInvalidIPRange)
	}
	startU := uint32(start4[0])<<24 | uint32(start4[1])<<16 | uint32(start4[2])<<8 | uint32(start4[3])
	endU := uint32(end4[0])<<24 | uint32(end4[1])<<16 | uint32(end4[2])<<8 | uint32(end4[3])
	// Cap the range size to protect against accidental huge ranges (e.g.
	// "10.0.0.0-10.255.255.255"). 65536 covers any realistic /16-equivalent
	// range; larger needs should use CIDR + the async task API.
	const maxRangeIPs = 65536
	count := int(endU-startU) + 1
	if count > maxRangeIPs {
		return nil, fmt.Errorf("%w: %d IPs (max %d)", ErrTargetRangeTooLarge, count, maxRangeIPs)
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
