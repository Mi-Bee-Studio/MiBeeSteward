// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/testutil"
)

// These tests pin the SNMP-credential handler's security invariants (#171):
//   - With no master_key configured, mutating endpoints are DISABLED (503) —
//     SNMPv3 passphrases can't be stored unencrypted.
//   - The encrypted auth/priv passphrases NEVER appear in any API response —
//     only HasAuth/HasPriv booleans (so a credential is identifiable without
//     leaking its secret). A regression that echoes the *_enc column is a
//     credential-disclosure hole.

func setupCredentialHandler(t *testing.T) (*CredentialHandler, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	// nil cipher + nil resolver: mirrors a deployment without security.master_key
	// (the disabled-storage state). Get/List work without a cipher; Create/Update
	// are the disabled-path guards under test.
	return NewCredentialHandler(conn, nil, nil), conn
}

func TestCredentialHandler_NilCipher_CreateReturns503(t *testing.T) {
	h, _ := setupCredentialHandler(t)
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/snmp-credentials", strings.NewReader(`{}`)))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"Create with no master_key must be disabled (503), not store an unencrypted passphrase")
}

func TestCredentialHandler_NilCipher_UpdateReturns503(t *testing.T) {
	h, _ := setupCredentialHandler(t)
	rec := httptest.NewRecorder()
	h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/snmp-credentials/1", `{}`, "1"))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"Update with no master_key must be disabled (503)")
}

func TestCredentialHandler_Get_NotFound(t *testing.T) {
	h, _ := setupCredentialHandler(t)
	rec := httptest.NewRecorder()
	h.Get(rec, reqWithURLParam(http.MethodGet, "/api/v1/snmp-credentials/999", "", "999"))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestCredentialHandler_Get_RedactsPassphrases is the disclosure guard: a
// credential row holding ENCRYPTED passphrases must surface only the
// HasAuth/HasPriv booleans — the encrypted secret value must never appear in
// the response body.
func TestCredentialHandler_Get_RedactsPassphrases(t *testing.T) {
	h, db := setupCredentialHandler(t)
	const secret = "SUPER-SECRET-ENCRYPTED-PASSPHRASE"
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO snmp_credentials
		  (name, security_level, community, username, auth_protocol, auth_passphrase_enc, priv_protocol, priv_passphrase_enc, notes)
		VALUES ('router-v3', 'authPriv', 'public', 'snmpv3user', 'SHA', ?, 'AES', ?, 'notes')`,
		secret, secret)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.Get(rec, reqWithURLParam(http.MethodGet, "/api/v1/snmp-credentials/1", "", "1"))
	require.Equal(t, http.StatusOK, rec.Code)

	// The encrypted passphrase must NOT leak into the API response.
	require.NotContains(t, rec.Body.String(), secret,
		"the encrypted passphrase must never appear in a credential response (disclosure guard)")

	// Only the boolean "is it set" indicators are exposed.
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Equal(t, true, resp["has_auth"], "has_auth surfaces without the passphrase")
	require.Equal(t, true, resp["has_priv"], "has_priv surfaces without the passphrase")
	// No passphrase-valued key exists at all.
	for _, k := range []string{"auth_passphrase", "priv_passphrase", "auth_passphrase_enc", "priv_passphrase_enc"} {
		require.NotContains(t, resp, k, "no passphrase field in response")
	}
}

// TestCredentialHandler_List_RedactsPassphrases extends the disclosure guard to
// the list endpoint (which uses a masked projection, but a regression that
// swaps in the full row would leak there too).
func TestCredentialHandler_List_RedactsPassphrases(t *testing.T) {
	h, db := setupCredentialHandler(t)
	const secret = "LIST-SECRET-ENC"
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO snmp_credentials
		  (name, security_level, community, username, auth_protocol, auth_passphrase_enc, priv_protocol, priv_passphrase_enc)
		VALUES ('list-v3', 'authPriv', 'public', 'u', 'SHA', ?, 'AES', ?)`, secret, secret)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/snmp-credentials", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), secret, "list response must not leak passphrases")
}
