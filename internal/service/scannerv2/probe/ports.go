// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package probe implements the ① Probe layer of scannerv2.
//
// Each ProbeSource gathers Evidence for one IP. Probes are domain-agnostic:
// they emit raw observations (port_open, banner bytes, SNMP varbinds, SOAP
// responses) and never decide what service is running — that's the
// Classifier's job.
//
// Active probes (this package) connect to the target. A passive eBPF observer
// lives in package ebpf (build-tag-gated).
package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// DefaultFingerprintPorts are scanned first (priority ordering) so that
// high-signal services are identified even when a fast-scan aborts mid-way.
// Derived from the legacy fingerprint set plus camera ports.
var DefaultFingerprintPorts = []int{
	22, 80, 443, 8080, 8443, 8000, // common web/admin
	554, 8554, // RTSP (cameras)
	9090, 9100, 9104, 9113, 9121, 9187, // prometheus family
	161,        // SNMP
	3306, 5432, // databases
}

const (
	maxConcurrentDials = 100
	bannerReadSize     = 1024
	bannerReadTimeout  = 3 * time.Second
)

// PortSpecProbe scans a TCP port spec ("22,80,100-200") with priority ports
// scanned first. For each open port it emits a port_open Evidence plus, when a
// banner can be passively read or actively elicited, a banner Evidence. It
// does NOT do protocol-specific probing (no HTTP GET, no RTSP OPTIONS) — that
// is the job of the dedicated protocol probes, which run after port discovery.
//
// Name: "active:tcp".
type PortSpecProbe struct {
	ports            string // port spec, e.g. "22,80,443,8080,554"
	fingerprintPorts []int  // scanned first; nil → use DefaultFingerprintPorts
}

// NewPortSpecProbe constructs a port probe. ports is the spec scanned; if empty
// the fingerprint ports are scanned.
func NewPortSpecProbe(ports string, fingerprintPorts []int) *PortSpecProbe {
	if fingerprintPorts == nil {
		fingerprintPorts = DefaultFingerprintPorts
	}
	return &PortSpecProbe{ports: ports, fingerprintPorts: fingerprintPorts}
}

func (p *PortSpecProbe) Name() string { return "active:tcp" }

// Probe dials every port in the spec concurrently, emits port_open + banner
// evidence for open ports. hint.PortSpec (a scan task's port whitelist)
// overrides the engine-global spec for this scan; hint.Timeout bounds each
// dial. hint.Ports is advisory and ignored.
func (p *PortSpecProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	spec := p.ports
	if hint.PortSpec != "" {
		spec = hint.PortSpec
	}
	if spec == "" {
		spec = joinInts(p.fingerprintPorts)
	}
	ports, err := priorityPortList(spec, p.fingerprintPorts)
	if err != nil {
		return nil, fmt.Errorf("active:tcp: invalid port spec: %w", err)
	}
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var (
		mu  sync.Mutex
		evs []scannerv2.Evidence
		wg  sync.WaitGroup
		sem = make(chan struct{}, maxConcurrentDials)
	)

	now := time.Now()
	for _, port := range ports {
		select {
		case <-ctx.Done():
			return evs, ctx.Err()
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			open, refused, banner := dialAndGrab(ctx, ip, port, timeout)
			mu.Lock()
			defer mu.Unlock()
			if !open {
				// A TCP RST is positive knowledge: the port is closed. Emit it
				// as negative evidence so the store can distinguish "confirmed
				// gone" (safe to drop the service row) from "no answer this
				// cycle" (timeout — keep the row; a degraded scan cycle must
				// not erase known services, #256).
				if refused {
					evs = append(evs, scannerv2.Evidence{
						Source:     "active:tcp",
						Kind:       "port_closed",
						IP:         ip,
						Port:       port,
						Protocol:   "tcp",
						Confidence: 1.0,
						ObservedAt: now,
					})
				}
				return
			}
			evs = append(evs, scannerv2.Evidence{
				Source:     "active:tcp",
				Kind:       "port_open",
				IP:         ip,
				Port:       port,
				Protocol:   "tcp",
				Confidence: 1.0,
				ObservedAt: now,
			})
			if banner != "" {
				evs = append(evs, scannerv2.Evidence{
					Source:     "active:tcp",
					Kind:       "banner",
					IP:         ip,
					Port:       port,
					Protocol:   "tcp",
					RawData:    map[string]string{"banner": banner},
					Confidence: 0.9,
					ObservedAt: now,
				})
			}
		}(port)
	}
	wg.Wait()
	return evs, nil
}

// dialAndGrab connects (TCP), and on success attempts a passive banner read.
// Many servers (SSH, RTSP, FTP, SMTP, redis) send a greeting immediately. If
// the passive read returns nothing AND the port has a known active probe
// string (e.g. HTTP "GET / HTTP/1.0"), the probe is sent and the response is
// read — this is what lets the port scan classify HTTP on ports where the
// server waits silently for a request.
//
// A dial that ends in RST (connection refused) is a CONFIRMED-closed port;
// a dial that runs out of time is UNKNOWN (filtered, or — commonly on busy
// routers (#256) — a transient drop under load). Unknown dials get one retry
// so a momentarily-saturated target isn't misread as closed.
//
// Returns (open, refused, banner).
func dialAndGrab(ctx context.Context, ip string, port int, timeout time.Duration) (bool, bool, string) {
	dialer := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if isRefused(err) {
			return false, true, ""
		}
		if ctx.Err() == nil && !isRefused(err) {
			// Transient (timeout / overloaded target / momentary drop): one
			// retry before declaring the port unknown.
			conn, err = dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return false, isRefused(err), ""
			}
		} else {
			return false, false, ""
		}
	}
	defer conn.Close()

	// Passive banner read: don't send anything; wait for a server greeting.
	// Catches SSH/FTP/SMTP/RTSP/redis/etc. that volunteer a banner on connect.
	// Loop until we get a newline (most greetings end with \r\n) or the read
	// deadline fires — handles slow servers (ProFTPD ident check) and segmented
	// greetings that arrive across TCP segments.
	_ = conn.SetReadDeadline(time.Now().Add(bannerReadTimeout))
	buf := make([]byte, bannerReadSize)
	n := 0
	for n < len(buf) {
		cn, err := conn.Read(buf[n:])
		n += cn
		if err != nil || cn == 0 {
			break
		}
		// Most banner greetings end with \r\n — stop after the first line.
		if bytes.ContainsRune(buf[:n], '\n') {
			break
		}
	}
	if n > 0 {
		return true, false, strings.TrimRight(string(buf[:n]), "\r\n\x00")
	}

	// No passive greeting: try the active probe for this port (if any). This
	// elicits a response from request/response services like HTTP.
	if probe := probeForPort(port); probe != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(bannerReadTimeout))
		if _, werr := conn.Write(probe); werr != nil {
			return true, false, ""
		}
		_ = conn.SetReadDeadline(time.Now().Add(bannerReadTimeout))
		n, _ = conn.Read(buf)
		return true, false, strings.TrimRight(string(buf[:n]), "\r\n\x00")
	}
	return true, false, ""
}

// isRefused reports whether the dial error is a TCP RST (ECONNREFUSED) — the
// kernel-level proof that nothing listens on the port. Everything else
// (timeout, no route, network unreachable) leaves the port's state unknown.
func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// priorityPortList orders ports with fingerprint ports first (in fingerprint
// order), then the remaining spec ports ascending, deduplicated. Mirrors the
// legacy behavior so fast-scan hits high-signal ports first.
func priorityPortList(spec string, fingerprintPorts []int) ([]int, error) {
	all, err := parsePortSpec(spec)
	if err != nil {
		return nil, err
	}
	if len(fingerprintPorts) == 0 {
		return all, nil
	}
	specSet := make(map[int]struct{}, len(all))
	for _, p := range all {
		specSet[p] = struct{}{}
	}
	fpSet := make(map[int]struct{}, len(fingerprintPorts))
	for _, p := range fingerprintPorts {
		if p >= 1 && p <= 65535 {
			fpSet[p] = struct{}{}
		}
	}
	result := make([]int, 0, len(all))
	seen := make(map[int]struct{})
	for _, fp := range fingerprintPorts {
		if _, inSpec := specSet[fp]; inSpec {
			if _, ok := seen[fp]; !ok {
				result = append(result, fp)
				seen[fp] = struct{}{}
			}
		}
	}
	for _, p := range all {
		if _, isFP := fpSet[p]; !isFP {
			result = append(result, p)
		}
	}
	return result, nil
}

// parsePortSpec parses "22,80,100-200" into a sorted, deduped []int.
func parsePortSpec(spec string) ([]int, error) {
	var out []int
	seen := make(map[int]struct{})
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "-"); i > 0 {
			lo, err1 := strconv.Atoi(part[:i])
			hi, err2 := strconv.Atoi(part[i+1:])
			if err1 != nil || err2 != nil || lo < 1 || hi < lo || hi > 65535 {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			if hi-lo > 10000 {
				return nil, fmt.Errorf("range %q too large (>10000)", part)
			}
			for p := lo; p <= hi; p++ {
				if _, ok := seen[p]; !ok {
					out = append(out, p)
					seen[p] = struct{}{}
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			if _, ok := seen[p]; !ok {
				out = append(out, p)
				seen[p] = struct{}{}
			}
		}
	}
	sort.Ints(out)
	return out, nil
}

func joinInts(in []int) string {
	parts := make([]string, len(in))
	for i, p := range in {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// readLine was removed (unused); protocol probes read banners inline.
