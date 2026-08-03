// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"mibee-steward/internal/service/scannerv2"
)

// TestV3MsgFlags_MapsSecurityLevels is the security-critical mapping test:
// each security level must map to the exact gosnmp MsgFlags bit field, because
// a wrong flag here would either (a) try to encrypt with no priv key (crash) or
// (b) silently send authless requests on a hardened target (defeat the purpose).
func TestV3MsgFlags_MapsSecurityLevels(t *testing.T) {
	cases := []struct {
		level string
		want  gosnmp.SnmpV3MsgFlags
	}{
		{scannerv2.SNMPLevelNoAuth, gosnmp.NoAuthNoPriv},
		{scannerv2.SNMPLevelAuthNoPriv, gosnmp.AuthNoPriv},
		{scannerv2.SNMPLevelAuthPriv, gosnmp.AuthPriv},
	}
	for _, tc := range cases {
		t.Run(tc.level, func(t *testing.T) {
			got, err := v3MsgFlags(tc.level)
			if err != nil {
				t.Fatalf("v3MsgFlags(%q): %v", tc.level, err)
			}
			if got != tc.want {
				t.Errorf("v3MsgFlags(%q) = %d, want %d", tc.level, got, tc.want)
			}
		})
	}
	// An invalid level must error (not silently default — that would mask a
	// typo as a wrong-but-working credential).
	if _, err := v3MsgFlags("bogus"); err == nil {
		t.Errorf("v3MsgFlags(\"bogus\") succeeded; want error")
	}
}

// TestParseAuthProtocol_ValidAndMissing covers the protocol string → enum
// mapping AND the rule that an authenticated level requires a protocol (so a
// misconfigured credential fails loudly at connect time, not as a silent
// noAuth downgrade that leaks the username in cleartext).
func TestParseAuthProtocol_ValidAndMissing(t *testing.T) {
	valid := []struct {
		proto string
		want  gosnmp.SnmpV3AuthProtocol
	}{
		{"MD5", gosnmp.MD5},
		{"SHA", gosnmp.SHA},
		{"SHA224", gosnmp.SHA224},
		{"SHA256", gosnmp.SHA256},
		{"SHA384", gosnmp.SHA384},
		{"SHA512", gosnmp.SHA512},
	}
	for _, tc := range valid {
		got, err := parseAuthProtocol(tc.proto, scannerv2.SNMPLevelAuthNoPriv)
		if err != nil {
			t.Errorf("parseAuthProtocol(%q): %v", tc.proto, err)
		}
		if got != tc.want {
			t.Errorf("parseAuthProtocol(%q) = %d, want %d", tc.proto, got, tc.want)
		}
	}
	// Empty protocol is valid ONLY for noAuthNoPriv.
	if _, err := parseAuthProtocol("", scannerv2.SNMPLevelNoAuth); err != nil {
		t.Errorf("parseAuthProtocol(\"\", noAuth): %v", err)
	}
	// Empty protocol on an authenticated level must error (no silent downgrade).
	if _, err := parseAuthProtocol("", scannerv2.SNMPLevelAuthNoPriv); err == nil {
		t.Errorf("parseAuthProtocol(\"\", authNoPriv) succeeded; want error")
	}
	// Unknown protocol must error.
	if _, err := parseAuthProtocol("ROT13", scannerv2.SNMPLevelAuthNoPriv); err == nil {
		t.Errorf("parseAuthProtocol(\"ROT13\") succeeded; want error")
	}
}

// TestParsePrivProtocol_ValidAndMissing mirrors the auth test for the privacy
// protocol. The key invariant: authPriv REQUIRES a priv protocol (an empty one
// would mean "encrypted... but not actually", a silent security hole).
func TestParsePrivProtocol_ValidAndMissing(t *testing.T) {
	valid := []struct {
		proto string
		want  gosnmp.SnmpV3PrivProtocol
	}{
		{"DES", gosnmp.DES},
		{"AES", gosnmp.AES},
		{"AES192", gosnmp.AES192},
		{"AES256", gosnmp.AES256},
		{"AES192C", gosnmp.AES192C},
		{"AES256C", gosnmp.AES256C},
	}
	for _, tc := range valid {
		got, err := parsePrivProtocol(tc.proto, scannerv2.SNMPLevelAuthPriv)
		if err != nil {
			t.Errorf("parsePrivProtocol(%q): %v", tc.proto, err)
		}
		if got != tc.want {
			t.Errorf("parsePrivProtocol(%q) = %d, want %d", tc.proto, got, tc.want)
		}
	}
	// Empty priv protocol is valid for non-priv levels.
	for _, lvl := range []string{scannerv2.SNMPLevelNoAuth, scannerv2.SNMPLevelAuthNoPriv} {
		if _, err := parsePrivProtocol("", lvl); err != nil {
			t.Errorf("parsePrivProtocol(\"\", %q): %v", lvl, err)
		}
	}
	// Empty priv on authPriv must error.
	if _, err := parsePrivProtocol("", scannerv2.SNMPLevelAuthPriv); err == nil {
		t.Errorf("parsePrivProtocol(\"\", authPriv) succeeded; want error")
	}
	// Unknown priv must error.
	if _, err := parsePrivProtocol("ROT13", scannerv2.SNMPLevelAuthPriv); err == nil {
		t.Errorf("parsePrivProtocol(\"ROT13\") succeeded; want error")
	}
}

// TestConnectSNMP_V3CredentialRoutesToV3 verifies that when a hint carries a v3
// credential, connectSNMP builds a Version3 client (NOT v2c) with the USM
// parameters populated. We don't dial a real agent here — we just confirm the
// credential selection + struct population is correct. The connection attempt
// to a non-listening port fails fast, which lets us inspect the configured
// struct before the dial without a running SNMP server.
func TestConnectSNMP_V3CredentialRoutesToV3(t *testing.T) {
	cred := &scannerv2.SNMPCredential{
		ID:             1,
		Name:           "test-v3",
		SecurityLevel:  scannerv2.SNMPLevelAuthPriv,
		UserName:       "testuser",
		AuthProtocol:   "SHA256",
		AuthPassphrase: "authpass8",
		PrivProtocol:   "AES",
		PrivPassphrase: "privpass8",
	}
	hint := scannerv2.ProbeHint{
		Timeout:        200 * time.Millisecond,
		SNMPCredential: cred,
	}
	// connectSNMPWithRetries returns the configured client even though the dial
	// to 127.0.0.1:161 will fail (nothing listening) — actually Connect() dials
	// UDP which is connectionless, so it won't fail. We close immediately and
	// inspect the struct.
	snmp, err := connectSNMPWithRetries("127.0.0.1", hint, gosnmp.Version2c, 0)
	if err != nil {
		t.Fatalf("connectSNMPWithRetries v3: %v", err)
	}
	defer func() {
		if snmp.Conn != nil {
			snmp.Conn.Close()
		}
	}()
	if snmp.Version != gosnmp.Version3 {
		t.Errorf("Version = %d, want Version3 (%d)", snmp.Version, gosnmp.Version3)
	}
	// gosnmp.Connect() ORs in the Reportable bit (4) during the initial v3
	// discovery handshake (gosnmp.go:393), so the on-the-wire MsgFlags become
	// AuthPriv|Reportable = 7. We check the AuthPriv bits are SET, not exact
	// equality, to allow that library behavior.
	if snmp.MsgFlags&gosnmp.AuthPriv != gosnmp.AuthPriv {
		t.Errorf("MsgFlags = %d, want AuthPriv bits (%d) set", snmp.MsgFlags, gosnmp.AuthPriv)
	}
	if snmp.SecurityModel != gosnmp.UserSecurityModel {
		t.Errorf("SecurityModel = %d, want UserSecurityModel (%d)", snmp.SecurityModel, gosnmp.UserSecurityModel)
	}
	usm, ok := snmp.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		t.Fatalf("SecurityParameters is %T, want *UsmSecurityParameters", snmp.SecurityParameters)
	}
	if usm.UserName != "testuser" {
		t.Errorf("USM UserName = %q, want \"testuser\"", usm.UserName)
	}
	if usm.AuthenticationProtocol != gosnmp.SHA256 {
		t.Errorf("USM AuthProtocol = %d, want SHA256 (%d)", usm.AuthenticationProtocol, gosnmp.SHA256)
	}
	if usm.AuthenticationPassphrase != "authpass8" {
		t.Errorf("USM AuthPassphrase = %q, want \"authpass8\"", usm.AuthenticationPassphrase)
	}
	if usm.PrivacyProtocol != gosnmp.AES {
		t.Errorf("USM PrivProtocol = %d, want AES (%d)", usm.PrivacyProtocol, gosnmp.AES)
	}
	if usm.PrivacyPassphrase != "privpass8" {
		t.Errorf("USM PrivPassphrase = %q, want \"privpass8\"", usm.PrivacyPassphrase)
	}
}

// TestConnectSNMP_LegacyCommunityUsedWhenNoCred verifies the no-credential path
// still builds a v2c client with the hint's community — the backward-compat
// invariant for existing deployments that haven't created any v3 credentials.
func TestConnectSNMP_LegacyCommunityUsedWhenNoCred(t *testing.T) {
	hint := scannerv2.ProbeHint{
		Community: "private",
		Timeout:   200 * time.Millisecond,
	}
	snmp, err := connectSNMPWithRetries("127.0.0.1", hint, gosnmp.Version2c, 0)
	if err != nil {
		t.Fatalf("connectSNMPWithRetries legacy: %v", err)
	}
	defer func() {
		if snmp.Conn != nil {
			snmp.Conn.Close()
		}
	}()
	if snmp.Version != gosnmp.Version2c {
		t.Errorf("Version = %d, want Version2c", snmp.Version)
	}
	if snmp.Community != "private" {
		t.Errorf("Community = %q, want \"private\"", snmp.Community)
	}
	if snmp.SecurityParameters != nil {
		t.Errorf("SecurityParameters set on legacy client; want nil")
	}
}

// TestConnectSNMP_V1V2CCredentialCommunityWinsOverHint confirms that a v1/v2c
// credential's community takes precedence over the hint's legacy community —
// so a scan task that bound a credential is honored even when the global
// default community is also set in the hint.
func TestConnectSNMP_V1V2CCredentialCommunityWinsOverHint(t *testing.T) {
	cred := &scannerv2.SNMPCredential{
		SecurityLevel: scannerv2.SNMPLevelV1V2C,
		Community:     "from-credential",
	}
	hint := scannerv2.ProbeHint{
		Community:      "from-hint-default",
		Timeout:        200 * time.Millisecond,
		SNMPCredential: cred,
	}
	snmp, err := connectSNMPWithRetries("127.0.0.1", hint, gosnmp.Version2c, 0)
	if err != nil {
		t.Fatalf("connectSNMPWithRetries: %v", err)
	}
	defer func() {
		if snmp.Conn != nil {
			snmp.Conn.Close()
		}
	}()
	if snmp.Community != "from-credential" {
		t.Errorf("Community = %q, want \"from-credential\" (credential must win)", snmp.Community)
	}
}
