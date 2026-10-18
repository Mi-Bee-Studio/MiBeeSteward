// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package domain

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateProbeOptions_ModuleGating pins that fields foreign to a module
// are rejected instead of silently ignored (#605).
func TestValidateProbeOptions_ModuleGating(t *testing.T) {
	cases := []struct {
		name   string
		module string
		opts   ProbeOptions
		errSub string
	}{
		{"http accepts its own fields", "http", ProbeOptions{Method: "HEAD", Keyword: "ok"}, ""},
		{"http rejects dns fields", "http", ProbeOptions{Resolver: "223.5.5.5"}, "do not apply"},
		{"http rejects tcp fields", "http", ProbeOptions{Send: "x"}, "do not apply"},
		{"dns accepts its own fields", "dns", ProbeOptions{Record: "AAAA", Resolver: "223.5.5.5"}, ""},
		{"dns rejects http fields", "dns", ProbeOptions{Method: "GET"}, "do not apply"},
		{"tcp accepts its own fields", "tcp", ProbeOptions{Send: "PING", Expect: "PONG"}, ""},
		{"tcp rejects dns fields", "tcp", ProbeOptions{Record: "A"}, "do not apply"},
		{"icmp takes none", "icmp", ProbeOptions{Keyword: "x"}, "takes no options"},
		{"tls takes none", "tls", ProbeOptions{Expect: "x"}, "takes no options"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProbeOptions(tc.module, &tc.opts)
			if tc.errSub == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errSub)
		})
	}
}

// TestValidateProbeOptions_FieldRules pins the enum/bound rules.
func TestValidateProbeOptions_FieldRules(t *testing.T) {
	t.Run("http enums", func(t *testing.T) {
		require.Error(t, ValidateProbeOptions("http", &ProbeOptions{Method: "POST"}))
		require.Error(t, ValidateProbeOptions("http", &ProbeOptions{Keyword: "x", KeywordMode: "glob"}))
		require.Error(t, ValidateProbeOptions("http", &ProbeOptions{KeywordMode: "regex"}), "mode without keyword")
		require.Error(t, ValidateProbeOptions("http", &ProbeOptions{Keyword: strings.Repeat("k", 257)}))
	})
	t.Run("expected status bounds", func(t *testing.T) {
		require.NoError(t, ValidateProbeOptions("http", &ProbeOptions{ExpectedStatus: []int{200, 204}}))
		require.Error(t, ValidateProbeOptions("http", &ProbeOptions{ExpectedStatus: []int{99}}))
		require.Error(t, ValidateProbeOptions("http", &ProbeOptions{ExpectedStatus: []int{600}}))
	})
	t.Run("dns enums and resolver", func(t *testing.T) {
		require.Error(t, ValidateProbeOptions("dns", &ProbeOptions{Record: "MX"}))
		require.NoError(t, ValidateProbeOptions("dns", &ProbeOptions{Resolver: "223.5.5.5"}))
		require.NoError(t, ValidateProbeOptions("dns", &ProbeOptions{Resolver: "223.5.5.5:5353"}))
		require.Error(t, ValidateProbeOptions("dns", &ProbeOptions{Resolver: "223.5.5.5:0"}))
		require.Error(t, ValidateProbeOptions("dns", &ProbeOptions{Resolver: "udp://x"}))
	})
	t.Run("expected ips", func(t *testing.T) {
		require.NoError(t, ValidateProbeOptions("dns", &ProbeOptions{Record: "A", ExpectedIPs: []string{"93.184.216.34"}}))
		require.NoError(t, ValidateProbeOptions("dns", &ProbeOptions{Record: "AAAA", ExpectedIPs: []string{"2606:2800:220:1:248:1893:25c8:1946"}}))
		require.Error(t, ValidateProbeOptions("dns", &ProbeOptions{ExpectedIPs: []string{"not-an-ip"}}))
		require.Error(t, ValidateProbeOptions("dns", &ProbeOptions{Record: "TXT", ExpectedIPs: []string{"1.1.1.1"}}), "expected_ips is A/AAAA only")
	})
	t.Run("tcp bounds", func(t *testing.T) {
		require.NoError(t, ValidateProbeOptions("tcp", &ProbeOptions{Expect: "SSH-2.0", ExpectMode: "contains"}))
		require.Error(t, ValidateProbeOptions("tcp", &ProbeOptions{ExpectMode: "regex"}), "mode without expect")
		require.Error(t, ValidateProbeOptions("tcp", &ProbeOptions{Expect: "x", ExpectMode: "glob"}))
	})
	t.Run("nil and empty pass", func(t *testing.T) {
		require.NoError(t, ValidateProbeOptions("http", nil))
		require.NoError(t, ValidateProbeOptions("icmp", &ProbeOptions{}))
	})
}

// TestValidateProbeTargetGrammar_DNS pins the dns module's target grammar:
// bare domain, no port, no path - the resolver is an option, not the target.
func TestValidateProbeTargetGrammar_DNS(t *testing.T) {
	require.NoError(t, ValidateProbeTargetGrammar("dns", "example.com"))
	require.NoError(t, ValidateProbeTargetGrammar("dns", "www.example.org"))
	require.Error(t, ValidateProbeTargetGrammar("dns", "example.com:53"))
	require.Error(t, ValidateProbeTargetGrammar("dns", "example.com/path"))
	require.Error(t, ValidateProbeTargetGrammar("dns", ""))
}

// TestValidateProbeTargetRequest_DNSModule wires the module through the full
// request validation (module whitelist + options + grammar).
func TestValidateProbeTargetRequest_DNSModule(t *testing.T) {
	require.NoError(t, ValidateProbeTargetRequest(ProbeTargetRequest{
		Name: "dns-x", Module: "dns", Target: "example.com",
		IntervalSeconds: 60, TimeoutSeconds: 5,
		Options: &ProbeOptions{Record: "A", Resolver: "223.5.5.5"},
	}))
	err := ValidateProbeTargetRequest(ProbeTargetRequest{
		Name: "dns-x", Module: "dns", Target: "example.com",
		IntervalSeconds: 60, TimeoutSeconds: 5,
		Options: &ProbeOptions{Keyword: "must fail"},
	})
	require.ErrorContains(t, err, "do not apply")
}
