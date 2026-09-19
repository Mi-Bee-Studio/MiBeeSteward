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
	"mibee-steward/internal/crypto"
	"mibee-steward/internal/testutil"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestCredentialHandler_NilCipherAndBadJSON pins the disabled-vault gate and
// the malformed-body branch (the handler surface before validation).
func TestCredentialHandler_NilCipherAndBadJSON(t *testing.T) {
	// Nil cipher → 503 on both Create and Update.
	hNil := NewCredentialHandler(nil, nil, nil)
	rec := httptest.NewRecorder()
	hNil.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/snmp-credentials", nil))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	rec = httptest.NewRecorder()
	hNil.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/snmp-credentials/1", `{}`, "1"))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	// Real cipher, malformed JSON → 400.
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	h := NewCredentialHandler(conn, cipher, nil)
	rec = httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/snmp-credentials", strings.NewReader(`{nope`)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = httptest.NewRecorder()
	h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/snmp-credentials/1", `{nope`, "1"))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = httptest.NewRecorder()
	h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/snmp-credentials/abc", `{}`, "abc"))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
