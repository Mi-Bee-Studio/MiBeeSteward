// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package classify

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestInferTypeFromSNMP_CharacterizationMatrix pins the sysServices×ifNumber
// heuristic's OBSERVED behavior as a regression snapshot (the gosnmpToInt bug
// class: a silent parse change here flips fleet-wide device types). Values
// were probed directly against the implementation; the bitmask semantics
// follow MIB-II sysServices bit positions (physical/datalink/internet/...).
func TestInferTypeFromSNMP_CharacterizationMatrix(t *testing.T) {
	cases := []struct {
		sv, ifn, want string
	}{
		{"78", "2", "router"}, // full stack, few interfaces
		{"72", "8", "server"}, // application-heavy, no datalink
		{"76", "2", "server"}, // application + internet, few interfaces
		{"3", "8", "switch"},  // physical+datalink, many interfaces
		{"7", "8", "switch"},  // physical+datalink+internet, many interfaces
		{"4", "2", ""},        // internet only: not decisive alone
		{"6", "5", ""},        // datalink+internet, mid interface count
		{"6", "30", ""},       // datalink+internet, many interfaces
		{"2", "52", ""},       // datalink only: not decisive without more bits
		{"0", "2", ""},        // no services
		{"x", "y", ""},        // junk numerics
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, inferTypeFromSNMP(tc.sv, "", "", tc.ifn),
			"sv=%s ifNumber=%s", tc.sv, tc.ifn)
	}
}

// TestSNMPClassifier_ClassifyArms drives the classifier's early return (no
// SNMP evidence) and the merged-varbind metadata shape.
func TestSNMPClassifier_ClassifyArms(t *testing.T) {
	c := SNMPClassifier{}

	// No snmp evidence → no assertion.
	require.Empty(t, c.Classify([]scannerv2.Evidence{
		{Kind: "port_open", IP: "10.0.0.1", Port: 80},
	}))

	out := c.Classify([]scannerv2.Evidence{
		{Kind: "snmp", IP: "10.0.0.1", RawData: map[string]string{
			"sys_descr":    "Linux NAS 5.x",
			"sys_services": "7",
			"if_number":    "8",
		}},
	})
	require.NotEmpty(t, out)
	require.Equal(t, "snmp", out[0].Service)
	require.Equal(t, "Linux NAS 5.x", out[0].Metadata["sys_descr"])
}
