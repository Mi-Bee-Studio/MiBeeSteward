// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// executeDNS runs the dns module (#605): resolve the target name (A/AAAA/
// CNAME/TXT), optionally against an explicit resolver (the egress-quality
// differential probes pin public resolvers per target). Latency is the whole
// resolution; expected_ips turns an answer mismatch into a fail.
func (x *targetExecutor) executeDNS(ctx context.Context, t db.ProbeTarget, timeout time.Duration) outcome {
	opts := parseProbeOptions(t.Options)
	record := domain.ProbeRecordA
	resolver := ""
	var expectedIPs []string
	if opts != nil {
		if opts.Record != "" {
			record = opts.Record
		}
		resolver = strings.TrimSpace(opts.Resolver)
		expectedIPs = opts.ExpectedIPs
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := net.DefaultResolver
	if resolver != "" {
		res = customResolver(resolver, timeout)
	}

	start := time.Now()
	var fail string
	var addrs []string
	switch record {
	case domain.ProbeRecordA:
		ips, err := res.LookupIP(ctx, "ip4", t.Target)
		addrs = ipStrings(ips)
		fail = resolveErr(err)
	case domain.ProbeRecordAAAA:
		ips, err := res.LookupIP(ctx, "ip6", t.Target)
		addrs = ipStrings(ips)
		fail = resolveErr(err)
	case domain.ProbeRecordCNAME:
		cname, err := res.LookupCNAME(ctx, t.Target)
		addrs = []string{strings.TrimSuffix(cname, ".")}
		fail = resolveErr(err)
	case domain.ProbeRecordTXT:
		txts, err := res.LookupTXT(ctx, t.Target)
		addrs = txts
		fail = resolveErr(err)
	default:
		return outcome{Status: "fail", ErrMsg: "unsupported dns record " + record}
	}
	elapsed := time.Since(start)

	if fail != "" {
		return outcome{Status: classifyError(fail), Latency: elapsed, ErrMsg: fail}
	}
	if len(expectedIPs) > 0 && (record == domain.ProbeRecordA || record == domain.ProbeRecordAAAA) {
		if !intersects(expectedIPs, addrs) {
			return outcome{
				Status:  "fail",
				Latency: elapsed,
				ErrMsg:  fmt.Sprintf("resolved %v does not intersect expected_ips %v", addrs, expectedIPs),
			}
		}
	}
	return outcome{Status: "success", Latency: elapsed}
}

// customResolver builds a PreferGo resolver that dials one pinned resolver
// (host or host:port; 53 implied) over UDP, ignoring the system resolv.conf.
func customResolver(resolver string, timeout time.Duration) *net.Resolver {
	addr := resolver
	if _, _, err := net.SplitHostPort(resolver); err != nil {
		addr = net.JoinHostPort(resolver, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// resolveErr renders a lookup failure; a nil error is success.
func resolveErr(err error) string {
	if err == nil {
		return ""
	}
	if strings.Contains(err.Error(), "no such host") {
		return "NXDOMAIN: no such host"
	}
	return err.Error()
}

func intersects(want, got []string) bool {
	for _, w := range want {
		for _, g := range got {
			if strings.EqualFold(w, g) {
				return true
			}
		}
	}
	return false
}
