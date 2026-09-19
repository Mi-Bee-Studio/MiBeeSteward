// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler_test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBatchEndpoints_BodyValidation: malformed/empty bodies and bad id lists
// are 400s before the service is touched.
func TestBatchEndpoints_BodyValidation(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	cases := []struct {
		path string
		body string
	}{
		{"/api/v1/devices/batch-delete", `{nope`},
		{"/api/v1/devices/batch-delete", `{}`},
		{"/api/v1/devices/batch-delete", `{"ids":[-1]}`},
		{"/api/v1/devices/batch-update-status", `{nope`},
		{"/api/v1/devices/batch-update-status", `{"ids":[1]}`},
		{"/api/v1/devices/batch-update-status", `{"ids":[-2],"status":"online"}`},
		{"/api/v1/users/batch-delete", `{nope`},
		{"/api/v1/users/batch-delete", `{"ids":[]}`},
		{"/api/v1/users/batch-delete", `{"ids":[0]}`},
	}
	for _, tc := range cases {
		resp := authPost(t, server.URL+tc.path, token, tc.body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "path %s body %s", tc.path, tc.body)
	}
}

// TestDocumentEndpoints_CreateURLValidation + Delete branches.
func TestDocumentEndpoints_CreateURLAndDelete(t *testing.T) {
	fx := setupGapServer(t)
	server, db := fx.server, fx.db
	token := fx.adminTok(t)

	resp := authPost(t, server.URL+"/api/v1/documents", token, `{nope`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+"/api/v1/documents", token, `{"title":""}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "title")
	// title-only without url: the service 404s?? — actually CreateURL requires
	// url; observed behavior is 400 via ErrURLRequired. Keep the observed 400.
	resp = authPost(t, server.URL+"/api/v1/documents", token, `{"title":"x"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	resp = authPost(t, server.URL+"/api/v1/documents", token, `{"title":"d","url":"https://x.example"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var doc map[string]interface{}
	decodeJSON(t, resp, &doc)
	id := idToString(doc["id"])

	resp = authDelete(t, server.URL+"/api/v1/documents/"+id, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authDelete(t, server.URL+"/api/v1/documents/"+id, token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authDelete(t, server.URL+"/api/v1/documents/abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	_ = db
}

// TestDeviceSystem_UpdateInvalidID + Get invalid family id branches.
func TestDeviceSystem_IDValidation(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	devID := seedCoverageDevice(t, db, "sys-id-host", "10.160.0.1")

	resp := authPut(t, server.URL+"/api/v1/devices/xyz/systems/1", token, `{"name":"x"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPut(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(devID, 10)+"/systems/abc", token, `{"name":"x"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+"/api/v1/devices/xyz/systems", token, `{"name":"x"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
