// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/crypto"
	"mibee-steward/internal/testutil"
)

// sshIDToStr stringifies a JSON-decoded id (float64) for URL paths.
func sshIDToStr(v any) string {
	switch n := v.(type) {
	case float64:
		return fmt.Sprintf("%d", int64(n))
	default:
		return fmt.Sprint(v)
	}
}

// These tests pin the SSH credential handler (#137). The load-bearing security
// contracts, mirroring the SNMP credential handler (#212):
//   - a nil cipher (no master_key) disables mutation (503),
//   - the plaintext secret/passphrase NEVER appear in any response (redaction),
//   - the validation + 404/409 error mapping.

// setupSSHCredHandler builds a handler over a fresh DB with a REAL 32-byte
// cipher (so Create can encrypt). Returns the handler + the db (for seeding).
func setupSSHCredHandler(t *testing.T) (*SSHCredentialHandler, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	cipher, err := crypto.NewCipher(make([]byte, crypto.MasterKeyLen))
	require.NoError(t, err)
	return NewSSHCredentialHandler(conn, cipher), conn
}

const sshCreateBody = `{"name":"core-sw","auth_method":"password","username":"admin","secret":"SUPER-SECRET-PW","host_key_fp":"SHA256:abc","enabled":true}`

func TestSSHCredentialHandler_Create_RedactsSecret(t *testing.T) {
	h, _ := setupSSHCredHandler(t)
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials", strings.NewReader(sshCreateBody)))

	require.Equal(t, http.StatusCreated, rec.Code)
	// The plaintext MUST NOT leak into the response.
	require.NotContains(t, rec.Body.String(), "SUPER-SECRET-PW", "plaintext secret must never be returned")
	var resp map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "core-sw", resp["name"])
	require.Equal(t, true, resp["has_secret"], "has_secret surfaces without the value")
	require.NotContains(t, resp, "secret", "no secret field in response")
	require.NotContains(t, resp, "secret_enc", "no ciphertext field in response")
}

func TestSSHCredentialHandler_NilCipher_CreateReturns503(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	h := NewSSHCredentialHandler(conn, nil) // no master key

	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials", strings.NewReader(sshCreateBody)))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "no master key -> mutation disabled (503)")
}

func TestSSHCredentialHandler_Create_InvalidAuthMethod(t *testing.T) {
	h, _ := setupSSHCredHandler(t)
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials",
		strings.NewReader(`{"name":"x","auth_method":"biometric","secret":"p"}`)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSSHCredentialHandler_Create_DuplicateName_Conflict(t *testing.T) {
	h, _ := setupSSHCredHandler(t)
	rec1 := httptest.NewRecorder()
	h.Create(rec1, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials", strings.NewReader(sshCreateBody)))
	require.Equal(t, http.StatusCreated, rec1.Code)

	rec2 := httptest.NewRecorder()
	h.Create(rec2, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials", strings.NewReader(sshCreateBody)))
	require.Equal(t, http.StatusConflict, rec2.Code)
}

func TestSSHCredentialHandler_Get_RedactsAndNotFound(t *testing.T) {
	h, _ := setupSSHCredHandler(t)
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials", strings.NewReader(sshCreateBody)))
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := sshIDToStr(created["id"])

	// Get redacts.
	rec = httptest.NewRecorder()
	h.Get(rec, reqWithURLParam(http.MethodGet, "/api/v1/ssh-credentials/"+id, "", id))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "SUPER-SECRET-PW")

	// Not-found.
	rec = httptest.NewRecorder()
	h.Get(rec, reqWithURLParam(http.MethodGet, "/api/v1/ssh-credentials/999", "", "999"))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestSSHCredentialHandler_List_Redacts(t *testing.T) {
	h, _ := setupSSHCredHandler(t)
	h.Create(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials", strings.NewReader(sshCreateBody)))

	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ssh-credentials", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "SUPER-SECRET-PW", "list must not leak plaintext")
}

func TestSSHCredentialHandler_Update_BlankSecretKeepsExisting(t *testing.T) {
	h, _ := setupSSHCredHandler(t)
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials", strings.NewReader(sshCreateBody)))
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := sshIDToStr(created["id"])

	// Rename with a BLANK secret -> existing ciphertext preserved (no re-enter).
	rec = httptest.NewRecorder()
	h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/ssh-credentials/"+id,
		`{"name":"core-sw-renamed","auth_method":"password","secret":""}`, id))
	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "core-sw-renamed", resp["name"])
	require.Equal(t, true, resp["has_secret"], "blank secret on update keeps the existing one")
}

func TestSSHCredentialHandler_Delete(t *testing.T) {
	h, _ := setupSSHCredHandler(t)
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials", strings.NewReader(sshCreateBody)))
	var created map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	id := sshIDToStr(created["id"])

	rec = httptest.NewRecorder()
	h.Delete(rec, reqWithURLParam(http.MethodDelete, "/api/v1/ssh-credentials/"+id, "", id))
	require.Equal(t, http.StatusNoContent, rec.Code)

	// Gone.
	rec = httptest.NewRecorder()
	h.Get(rec, reqWithURLParam(http.MethodGet, "/api/v1/ssh-credentials/"+id, "", id))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

// keep these imports used (context for future seed helpers)
var _ = context.Background
