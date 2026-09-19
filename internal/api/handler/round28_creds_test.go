// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/crypto"
)

// TestCredentialHandlers_DeadDB_Sweep drives the SNMP + SSH credential
// handlers over a dead handle: every storage-touching branch surfaces a 500
// (create insert, list, get, update fetch, delete) without panicking, and
// the pure validation arms (bad body / bad ID / missing fields) answer 400.
func TestCredentialHandlers_DeadDB_Sweep(t *testing.T) {
	conn := closedTestDB(t)
	cipher, err := crypto.NewCipher(make([]byte, crypto.MasterKeyLen))
	require.NoError(t, err)

	snmp := NewCredentialHandler(conn, cipher, nil)
	ssh := NewSSHCredentialHandler(conn, cipher)

	// --- validation arms (no storage touched) ---
	r := httptest.NewRecorder()
	snmp.Create(r, reqWithBodyParams(http.MethodPost, "/api/v1/snmp-credentials", "not json", nil))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	snmp.Create(r, reqWithBodyParams(http.MethodPost, "/api/v1/snmp-credentials", `{}`, nil))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	ssh.Create(r, reqWithBodyParams(http.MethodPost, "/api/v1/ssh-credentials", "not json", nil))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	ssh.Create(r, reqWithBodyParams(http.MethodPost, "/api/v1/ssh-credentials", `{}`, nil))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	ssh.Create(r, reqWithBodyParams(http.MethodPost, "/api/v1/ssh-credentials",
		`{"name":"x","auth_method":"bogus"}`, nil))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	ssh.Get(r, reqWithBodyParams(http.MethodGet, "/api/v1/ssh-credentials/abc", "",
		map[string]string{"id": "abc"}))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	ssh.Update(r, reqWithBodyParams(http.MethodPut, "/api/v1/ssh-credentials/abc", `{}`,
		map[string]string{"id": "abc"}))
	require.Equal(t, http.StatusBadRequest, r.Code)

	r = httptest.NewRecorder()
	ssh.Delete(r, reqWithBodyParams(http.MethodDelete, "/api/v1/ssh-credentials/abc", "",
		map[string]string{"id": "abc"}))
	require.Equal(t, http.StatusBadRequest, r.Code)

	// --- storage arms over the dead handle: 500s ---
	r = httptest.NewRecorder()
	snmp.Create(r, reqWithBodyParams(http.MethodPost, "/api/v1/snmp-credentials",
		`{"name":"v3","security_level":"authPriv","username":"u","auth_protocol":"SHA","auth_passphrase":"authsec1","priv_protocol":"AES","priv_passphrase":"privsec1"}`, nil))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	snmp.List(r, httptest.NewRequest(http.MethodGet, "/api/v1/snmp-credentials", nil))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	snmp.Get(r, reqWithBodyParams(http.MethodGet, "/api/v1/snmp-credentials/1", "",
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	snmp.Update(r, reqWithBodyParams(http.MethodPut, "/api/v1/snmp-credentials/1",
		`{"name":"v3","security_level":"authPriv","username":"u","auth_protocol":"SHA","auth_passphrase":"authsec1","priv_protocol":"AES","priv_passphrase":"privsec1"}`,
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	snmp.Delete(r, reqWithBodyParams(http.MethodDelete, "/api/v1/snmp-credentials/1", "",
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	ssh.Create(r, reqWithBodyParams(http.MethodPost, "/api/v1/ssh-credentials",
		`{"name":"sw","auth_method":"password","username":"admin","secret":"pw"}`, nil))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	ssh.List(r, httptest.NewRequest(http.MethodGet, "/api/v1/ssh-credentials", nil))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	ssh.Get(r, reqWithBodyParams(http.MethodGet, "/api/v1/ssh-credentials/1", "",
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	ssh.Update(r, reqWithBodyParams(http.MethodPut, "/api/v1/ssh-credentials/1",
		`{"name":"sw","auth_method":"password"}`, map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	ssh.Delete(r, reqWithBodyParams(http.MethodDelete, "/api/v1/ssh-credentials/1", "",
		map[string]string{"id": "1"}))
	require.Equal(t, http.StatusInternalServerError, r.Code)
}
