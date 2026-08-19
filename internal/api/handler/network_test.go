// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service"
	"mibee-steward/internal/testutil"
)

// These are characterization tests for NetworkHandler (#171). network.go is #166
// charter debt: a mutating handler that uses raw *db.Queries directly (not the
// service layer). It is the documented prerequisite safety net for the #157
// handler-collapse refactor. The tests lock the CRUD behavior directly against
// the handler (injecting chi URL params), covering the parse/validate/error-map
// logic + the trim + agent_id-not-editable invariants.

func setupNetworkHandler(t *testing.T) (*NetworkHandler, *db.Queries, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	return NewNetworkHandler(queries, service.NewNetworkService(queries, conn)), queries, conn
}

// reqWithURLParam builds a request with a chi "id" URL param injected, so
// Update/Delete (which call chi.URLParam(r, "id")) work outside a full router.
func reqWithURLParam(method, target, body, id string) *http.Request {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rdr)
	rctx := chi.NewRouteContext()
	if id != "" {
		rctx.URLParams.Add("id", id)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	require.NoError(t, json.NewDecoder(rec.Body).Decode(out))
}

// --- List ---

func TestNetworkHandler_List_ReturnsAllOrdered(t *testing.T) {
	h, q, _ := setupNetworkHandler(t)
	ctx := context.Background()
	_, err := q.CreateNetwork(ctx, db.CreateNetworkParams{Name: "lan-b"})
	require.NoError(t, err)
	_, err = q.CreateNetwork(ctx, db.CreateNetworkParams{Name: "lan-a"})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/networks", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var nets []map[string]any
	decodeBody(t, rec, &nets)
	require.Len(t, nets, 2)
	// ListNetworks orders by id → creation order.
	require.Equal(t, "lan-b", nets[0]["name"])
	require.Equal(t, "lan-a", nets[1]["name"])
}

// --- Create ---

func TestNetworkHandler_Create_Success(t *testing.T) {
	h, _, _ := setupNetworkHandler(t)
	cidr, site := "10.0.0.0/24", "hq"
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/networks",
		strings.NewReader(`{"name":"  lan-63  ","cidr":"`+cidr+`","site":"`+site+`"}`)))

	require.Equal(t, http.StatusCreated, rec.Code)
	var got map[string]any
	decodeBody(t, rec, &got)
	require.Equal(t, "lan-63", got["name"], "name must be trimmed")
	require.Equal(t, cidr, got["cidr"])
	require.Equal(t, site, got["site"])
	require.Nil(t, got["agent_id"], "a fresh network has no agent until a token is minted")
}

func TestNetworkHandler_Create_InvalidBody(t *testing.T) {
	h, _, _ := setupNetworkHandler(t)
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/networks", strings.NewReader("not-json")))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestNetworkHandler_Create_EmptyName(t *testing.T) {
	h, _, _ := setupNetworkHandler(t)
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/networks",
		strings.NewReader(`{"name":"   "}`)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestNetworkHandler_Create_DuplicateName_Conflict(t *testing.T) {
	h, _, _ := setupNetworkHandler(t)
	body := strings.NewReader(`{"name":"lan-dup"}`)
	rec1 := httptest.NewRecorder()
	h.Create(rec1, httptest.NewRequest(http.MethodPost, "/api/v1/networks", body))
	require.Equal(t, http.StatusCreated, rec1.Code)

	rec2 := httptest.NewRecorder()
	h.Create(rec2, httptest.NewRequest(http.MethodPost, "/api/v1/networks",
		strings.NewReader(`{"name":"lan-dup"}`)))
	require.Equal(t, http.StatusConflict, rec2.Code, "duplicate name → 409 (networks.name is UNIQUE)")
}

// --- Update ---

func TestNetworkHandler_Update_Success(t *testing.T) {
	h, q, _ := setupNetworkHandler(t)
	ctx := context.Background()
	net, err := q.CreateNetwork(ctx, db.CreateNetworkParams{Name: "old"})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/networks/"+itoa(net.ID),
		`{"name":"new","cidr":"172.16.0.0/16","site":"branch"}`, itoa(net.ID)))

	require.Equal(t, http.StatusOK, rec.Code)
	var got map[string]any
	decodeBody(t, rec, &got)
	require.Equal(t, "new", got["name"])
	require.Equal(t, "172.16.0.0/16", got["cidr"])
}

func TestNetworkHandler_Update_NotFound(t *testing.T) {
	h, _, _ := setupNetworkHandler(t)
	rec := httptest.NewRecorder()
	h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/networks/999",
		`{"name":"x"}`, "999"))
	require.Equal(t, http.StatusNotFound, rec.Code, "updating a non-existent network → 404")
}

func TestNetworkHandler_Update_InvalidID(t *testing.T) {
	h, _, _ := setupNetworkHandler(t)
	rec := httptest.NewRecorder()
	h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/networks/abc",
		`{"name":"x"}`, "abc"))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestNetworkHandler_Update_EmptyName(t *testing.T) {
	h, q, _ := setupNetworkHandler(t)
	ctx := context.Background()
	net, err := q.CreateNetwork(ctx, db.CreateNetworkParams{Name: "n"})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/networks/"+itoa(net.ID),
		`{"name":""}`, itoa(net.ID)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestNetworkHandler_Update_DuplicateName_Conflict(t *testing.T) {
	h, q, _ := setupNetworkHandler(t)
	ctx := context.Background()
	_, err := q.CreateNetwork(ctx, db.CreateNetworkParams{Name: "taken"})
	require.NoError(t, err)
	net, err := q.CreateNetwork(ctx, db.CreateNetworkParams{Name: "other"})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/networks/"+itoa(net.ID),
		`{"name":"taken"}`, itoa(net.ID)))
	require.Equal(t, http.StatusConflict, rec.Code, "renaming onto an existing name → 409")
}

// TestNetworkHandler_Update_AgentIDNotEditable pins the charter invariant that
// agent_id is owned by the agent-token flow, NOT the network editor: a PUT must
// update name/cidr/site while leaving an existing agent_id untouched. (A future
// service-layer migration must preserve this.)
func TestNetworkHandler_Update_AgentIDNotEditable(t *testing.T) {
	h, q, conn := setupNetworkHandler(t)
	ctx := context.Background()
	net, err := q.CreateNetwork(ctx, db.CreateNetworkParams{Name: "agent-net"})
	require.NoError(t, err)
	// Stamp an agent_id directly (the token flow does this), since Create can't.
	_, err = conn.ExecContext(ctx, `UPDATE networks SET agent_id = ? WHERE id = ?`, "agent-62", net.ID)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.Update(rec, reqWithURLParam(http.MethodPut, "/api/v1/networks/"+itoa(net.ID),
		`{"name":"agent-net-renamed"}`, itoa(net.ID)))
	require.Equal(t, http.StatusOK, rec.Code)

	got, err := q.GetNetwork(ctx, net.ID)
	require.NoError(t, err)
	require.Equal(t, "agent-net-renamed", got.Name, "name updated")
	require.NotNil(t, got.AgentID, "agent_id must survive a name/cidr/site edit")
	require.Equal(t, "agent-62", *got.AgentID)
}

// --- Delete ---

func TestNetworkHandler_Delete_Success(t *testing.T) {
	h, q, _ := setupNetworkHandler(t)
	ctx := context.Background()
	net, err := q.CreateNetwork(ctx, db.CreateNetworkParams{Name: "goner"})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	h.Delete(rec, reqWithURLParam(http.MethodDelete, "/api/v1/networks/"+itoa(net.ID), "", itoa(net.ID)))
	require.Equal(t, http.StatusNoContent, rec.Code)

	nets, err := q.ListNetworks(ctx)
	require.NoError(t, err)
	require.Empty(t, nets, "network must be gone after delete")
}

func TestNetworkHandler_Delete_InvalidID(t *testing.T) {
	h, _, _ := setupNetworkHandler(t)
	rec := httptest.NewRecorder()
	h.Delete(rec, reqWithURLParam(http.MethodDelete, "/api/v1/networks/abc", "", "abc"))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// itoa is a local int64→string helper for building request paths/params.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }
