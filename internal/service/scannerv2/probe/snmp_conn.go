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
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"

	"mibee-steward/internal/service/scannerv2"
)

// connectSNMP constructs and dials a gosnmp client configured with whichever
// credentials the hint carries, using gosnmp's default retry count (0 — most
// probes that need retries run their own bounded backoff loop). It is the
// SINGLE place that translates an scannerv2.SNMPCredential (library-neutral)
// into gosnmp's typed v3 USM parameters, so the 7 SNMP-speaking probes
// (snmp + 5 L2 + snmp_arp) don't each repeat that logic.
//
// Credential selection rules:
//   - hint carries an SNMPCredential with IsV3() == true  → SNMPv3 (USM)
//     with the credential's security level / auth / priv. `version` is IGNORED
//     (v3 is implied by the credential).
//   - hint carries an SNMPCredential with SecurityLevel=="v1v2c" → v1/v2c
//     using the credential's Community. `version` is honored (caller picks v2c
//     or v1 for the fallback ladder).
//   - hint.SNMPCredential is nil → legacy path: `community` (default "public")
//   - caller-supplied `version`.
//
// Returns a CONNECTED client (snmp.Conn is open) on success; the caller MUST
// defer snmp.Conn.Close(). Connect failures are returned as errors (NOT
// swallowed) so callers can distinguish "host unreachable" from "no SNMP data"
// when that distinction matters; most probes treat either as "no evidence".
func connectSNMP(ip string, hint scannerv2.ProbeHint, version gosnmp.SnmpVersion) (*gosnmp.GoSNMP, error) {
	return connectSNMPWithRetries(ip, hint, version, 0)
}

// connectSNMPWithRetries is the variant for probes that want gosnmp's built-in
// UDP retransmit (the L2 topology probes set Retries=1 so a single dropped
// LLDP/CDP/Bridge walk doesn't lose a neighbor). The retry count is per-Get;
// the probe's own timeout still bounds the total.
func connectSNMPWithRetries(ip string, hint scannerv2.ProbeHint, version gosnmp.SnmpVersion, retries int) (*gosnmp.GoSNMP, error) {
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// v3 path: the credential decides everything. hint.IsV3() is the promoted
	// embedded-field method (nil-safe — returns false when no credential).
	if hint.IsV3() {
		return connectV3(ip, hint.SNMPCredential, timeout, retries)
	}

	// v1/v2c path. A v1v2c credential's community wins over the legacy
	// hint.Community so a scan task that bound a credential is honored even
	// when the global default community is also set.
	community := hint.Community
	if hint.SNMPCredential != nil && hint.SNMPCredential.Community != "" {
		community = hint.SNMPCredential.Community
	}
	if community == "" {
		community = "public"
	}
	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   version,
		Timeout:   timeout,
		Retries:   retries,
	}
	if err := snmp.Connect(); err != nil {
		return nil, err
	}
	return snmp, nil
}

// connectV3 builds the v3 USM parameters from a credential and dials. The v3
// discovery handshake (engine ID / boots / time) is handled by gosnmp
// internally on the first request — we only supply the static USM identity.
func connectV3(ip string, cred *scannerv2.SNMPCredential, timeout time.Duration, retries int) (*gosnmp.GoSNMP, error) {
	authProto, err := parseAuthProtocol(cred.AuthProtocol, cred.SecurityLevel)
	if err != nil {
		return nil, fmt.Errorf("snmpv3 auth protocol: %w", err)
	}
	privProto, err := parsePrivProtocol(cred.PrivProtocol, cred.SecurityLevel)
	if err != nil {
		return nil, fmt.Errorf("snmpv3 priv protocol: %w", err)
	}

	msgFlags, err := v3MsgFlags(cred.SecurityLevel)
	if err != nil {
		return nil, err
	}

	snmp := &gosnmp.GoSNMP{
		Target:          ip,
		Port:            161,
		Version:         gosnmp.Version3,
		Timeout:         timeout,
		Retries:         retries,
		SecurityModel:   gosnmp.UserSecurityModel,
		MsgFlags:        msgFlags,
		ContextEngineID: "", // gosnmp auto-discovers the authoritative engine ID
		ContextName:     "",
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 cred.UserName,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: cred.AuthPassphrase,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        cred.PrivPassphrase,
		},
	}
	if err := snmp.Connect(); err != nil {
		return nil, err
	}
	return snmp, nil
}

// v3MsgFlags maps a security-level string to the gosnmp MsgFlags bit field.
// noAuthNoPriv=0x0, authNoPriv=0x1, authPriv=0x3 (the high bit is "reportable"
// during discovery; gosnmp sets that internally so we don't).
func v3MsgFlags(securityLevel string) (gosnmp.SnmpV3MsgFlags, error) {
	switch securityLevel {
	case scannerv2.SNMPLevelNoAuth:
		return gosnmp.NoAuthNoPriv, nil
	case scannerv2.SNMPLevelAuthNoPriv:
		return gosnmp.AuthNoPriv, nil
	case scannerv2.SNMPLevelAuthPriv:
		return gosnmp.AuthPriv, nil
	default:
		return 0, fmt.Errorf("unsupported v3 security level %q", securityLevel)
	}
}

// parseAuthProtocol maps a wire-string auth protocol to its gosnmp enum. The
// empty string is valid ONLY for noAuthNoPriv; for the authenticated levels we
// require a real protocol (defaulting to MD5 would mask a config typo as a
// silent downgrade, so we error instead).
func parseAuthProtocol(proto, securityLevel string) (gosnmp.SnmpV3AuthProtocol, error) {
	if proto == "" {
		if securityLevel == scannerv2.SNMPLevelNoAuth {
			return gosnmp.NoAuth, nil
		}
		return 0, fmt.Errorf("auth_protocol required for security level %q", securityLevel)
	}
	switch proto {
	case "MD5":
		return gosnmp.MD5, nil
	case "SHA":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	default:
		return 0, fmt.Errorf("unknown auth protocol %q", proto)
	}
}

// parsePrivProtocol maps a wire-string privacy protocol to its gosnmp enum.
// The empty string is valid ONLY when the security level has no privacy
// (noAuthNoPriv / authNoPriv); for authPriv we require a real protocol.
func parsePrivProtocol(proto, securityLevel string) (gosnmp.SnmpV3PrivProtocol, error) {
	if proto == "" {
		if securityLevel != scannerv2.SNMPLevelAuthPriv {
			return gosnmp.NoPriv, nil
		}
		return 0, fmt.Errorf("priv_protocol required for security level %q", securityLevel)
	}
	switch proto {
	case "DES":
		return gosnmp.DES, nil
	case "AES":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	default:
		return 0, fmt.Errorf("unknown priv protocol %q", proto)
	}
}
