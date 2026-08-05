// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package scannerv2

// SNMP credential model for issue #135 (SNMPv3 support).
//
// SNMPCredential is the in-process representation of one row from
// snmp_credentials, AFTER the encrypted *_passphrase fields have been
// decrypted by the credential resolver (internal/service/scannerv2/credresolver).
// It is carried through the scan pipeline via ProbeHint (see evidence.go) and
// read by every SNMP-speaking probe via the shared connectSNMP helper
// (probe/snmp_conn.go).
//
// Design choice: this type lives in the scannerv2 root package (NOT probe/) and
// intentionally uses NEUTRAL string fields for the protocol identifiers rather
// than gosnmp's typed enums (gosnmp.SnmpV3AuthProtocol etc.). The mapping from
// the wire string ("SHA256") to the gosnmp enum happens in exactly one place
// (connectSNMP). This keeps the scannerv2 package free of a direct gosnmp
// import — important because the orchestrator, engine config, and credential
// resolver all touch this type, and none of them should depend on the SNMP
// client library.

// SNMPCredential holds the credentials for one SNMP authentication identity.
// The zero value is not meaningful — construct via the credential resolver,
// which decrypts the DB row. A credential is EITHER a v1/v2c community
// (SecurityLevel=="v1v2c", Community set) OR an SNMPv3 USM credential (one of
// the v3 security levels, USM fields set).
type SNMPCredential struct {
	// ID is the snmp_credentials.id (0 for an ad-hoc credential not from the DB,
	// e.g. one synthesized from the legacy per-request community string).
	ID int64 `json:"id,omitempty"`
	// Name is the user-facing label (informational; not sent on the wire).
	Name string `json:"name,omitempty"`

	// SecurityLevel selects the authentication model. One of:
	//   "v1v2c"        — community-string auth (Community field used)
	//   "noAuthNoPriv" — SNMPv3 USM, no auth, no privacy (RFC 3414 level 1)
	//   "authNoPriv"   — SNMPv3 USM, authenticated, unencrypted (level 2)
	//   "authPriv"     — SNMPv3 USM, authenticated + encrypted (level 3)
	SecurityLevel string `json:"security_level"`

	// Community is the v1/v2c community string. Used ONLY when
	// SecurityLevel=="v1v2c"; empty otherwise.
	Community string `json:"community,omitempty"`

	// UserName is the SNMPv3 USM security name. Empty for v1/v2c.
	UserName string `json:"username,omitempty"`
	// AuthProtocol is the SNMPv3 authentication protocol, one of
	// ""|"MD5"|"SHA"|"SHA224"|"SHA256"|"SHA384"|"SHA512". "" means no auth
	// (valid only for noAuthNoPriv). See probe.parseAuthProtocol for the mapping.
	AuthProtocol string `json:"auth_protocol,omitempty"`
	// AuthPassphrase is the plaintext USM auth passphrase (8+ chars per RFC
	// 3414). Held in memory only; NEVER persisted — the DB stores the
	// AES-GCM ciphertext, decrypted by the credential resolver on read.
	AuthPassphrase string `json:"-"`
	// PrivProtocol is the SNMPv3 privacy (encryption) protocol, one of
	// ""|"DES"|"AES"|"AES192"|"AES256"|"AES192C"|"AES256C". "" means no privacy
	// (valid only for noAuthNoPriv / authNoPriv).
	PrivProtocol string `json:"priv_protocol,omitempty"`
	// PrivPassphrase is the plaintext USM priv passphrase. Same memory-only /
	// never-persisted contract as AuthPassphrase.
	PrivPassphrase string `json:"-"`
}

// IsV3 reports whether this credential selects the SNMPv3 protocol (vs the
// legacy v1/v2c community path). Probes branch on this to decide whether to
// attempt v3 or fall back through the v2c→v1 ladder.
func (c *SNMPCredential) IsV3() bool {
	if c == nil {
		return false
	}
	switch c.SecurityLevel {
	case "noAuthNoPriv", "authNoPriv", "authPriv":
		return true
	}
	return false
}

// SNMP credential security-level constants. Centralized here so callers
// (config validation, API handlers, tests) reference names, not magic strings.
const (
	SNMPLevelV1V2C      = "v1v2c"
	SNMPLevelNoAuth     = "noAuthNoPriv"
	SNMPLevelAuthNoPriv = "authNoPriv"
	SNMPLevelAuthPriv   = "authPriv"
)

// ValidSNMPSecurityLevels is the allow-list used by API input validation.
var ValidSNMPSecurityLevels = []string{
	SNMPLevelV1V2C, SNMPLevelNoAuth, SNMPLevelAuthNoPriv, SNMPLevelAuthPriv,
}

// IsValidSNMPSecurityLevel reports whether lvl is a recognized security level.
// Used by the credential handler to reject malformed input with a clear error.
func IsValidSNMPSecurityLevel(lvl string) bool {
	for _, v := range ValidSNMPSecurityLevels {
		if v == lvl {
			return true
		}
	}
	return false
}
