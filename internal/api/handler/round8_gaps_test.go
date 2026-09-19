// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateCredentialRequest_Matrix pins the SNMP credential API-boundary
// validation: every security level's required fields, with exact messages.
func TestValidateCredentialRequest_Matrix(t *testing.T) {
	cases := []struct {
		name    string
		req     snmpCredentialRequest
		wantErr string
	}{
		{"missing name", snmpCredentialRequest{SecurityLevel: "noAuthNoPriv"}, "name is required"},
		{"bad security level", snmpCredentialRequest{Name: "x", SecurityLevel: "warp"}, "security_level must be one of"},
		{"v1v2c without community", snmpCredentialRequest{Name: "x", SecurityLevel: "v1v2c"}, "community is required"},
		{"v1v2c ok", snmpCredentialRequest{Name: "x", SecurityLevel: "v1v2c", Community: "public"}, ""},
		{"noAuthNoPriv ok (username optional)", snmpCredentialRequest{Name: "x", SecurityLevel: "noAuthNoPriv"}, ""},
		{"authNoPriv without username", snmpCredentialRequest{Name: "x", SecurityLevel: "authNoPriv", AuthProtocol: "SHA"}, "username is required"},
		{"authNoPriv without protocol", snmpCredentialRequest{Name: "x", SecurityLevel: "authNoPriv", Username: "u"}, "auth_protocol is required"},
		{"authNoPriv ok", snmpCredentialRequest{Name: "x", SecurityLevel: "authNoPriv", Username: "u", AuthProtocol: "SHA"}, ""},
		{"authPriv without priv protocol", snmpCredentialRequest{Name: "x", SecurityLevel: "authPriv", Username: "u", AuthProtocol: "SHA"}, "priv_protocol is required"},
		{"authPriv ok", snmpCredentialRequest{Name: "x", SecurityLevel: "authPriv", Username: "u", AuthProtocol: "SHA", PrivProtocol: "AES"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCredentialRequest(&tc.req)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
