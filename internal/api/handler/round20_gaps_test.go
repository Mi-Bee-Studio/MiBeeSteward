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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/crypto"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
	"mibee-steward/internal/service/probetarget"
	"mibee-steward/internal/service/scannerv2/credresolver"
	"mibee-steward/internal/service/scannerv2/taskservice"
	"mibee-steward/internal/testutil"
)

// reqWithBodyParams builds a request with arbitrary chi URL params injected, the
// direct-invocation equivalent of a routed request (generalizes
// reqWithURLParam, which only handles "id").
func reqWithBodyParams(method, target, body string, params map[string]string) *http.Request {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rdr)
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// TestHandler_ValidationTailBranches sweeps the remaining no-context /
// empty-param early returns across endpoint families in one pass (white-box,
// direct handler invocation, no auth middleware → the
// GetUserFromContext-!ok guards fire too).
func TestHandler_ValidationTailBranches(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)

	auditRepo := service.NewAuditRepository(conn)
	totpH := NewTOTPHandler(service.NewTOTPService(conn, auditRepo),
		service.NewUserService(conn, "test-secret-key-for-tests-32-bytes!!", time.Hour, config.PasswordPolicyConfig{}),
		&config.Config{}, auditRepo)
	sysH := NewDeviceSystemHandler(service.NewDeviceSystemService(service.NewDeviceSystemRepository(conn)))
	cmdH := NewAgentCommandHandler(queries, service.NewAgentCommandService(queries, false, false), nil)
	admH := NewAgentAdminHandler(queries, service.NewAgentTokenService(queries))
	sshH, _ := setupSSHCredHandler(t)

	// TOTP Setup without auth context → 401.
	r := httptest.NewRecorder()
	totpH.Setup(r, httptest.NewRequest(http.MethodPost, "/api/v1/auth/2fa/setup", nil))
	require.Equal(t, http.StatusUnauthorized, r.Code)

	// Device-system Update: non-numeric device id → 400.
	r = httptest.NewRecorder()
	sysH.Update(r, reqWithBodyParams(http.MethodPut, "/api/v1/devices/abc/systems/1", `{}`, map[string]string{"id": "abc", "systemId": "1"}))
	require.Equal(t, http.StatusBadRequest, r.Code)

	// Agent command ListAll with bad pagination → 400.
	r = httptest.NewRecorder()
	cmdH.ListAll(r, httptest.NewRequest(http.MethodGet, "/api/v1/agents/commands/all?limit=zzz", nil))
	require.Equal(t, http.StatusBadRequest, r.Code)

	// FleetStatus on an empty DB → 200 with an empty fleet.
	r = httptest.NewRecorder()
	cmdH.FleetStatus(r, httptest.NewRequest(http.MethodGet, "/api/v1/agents/status", nil))
	require.Equal(t, http.StatusOK, r.Code)

	// Agent admin List on an empty DB → 200.
	r = httptest.NewRecorder()
	admH.List(r, httptest.NewRequest(http.MethodGet, "/api/v1/agents/tokens", nil))
	require.Equal(t, http.StatusOK, r.Code)

	// SSH credential Create with malformed JSON → 400.
	r = httptest.NewRecorder()
	sshH.Create(r, httptest.NewRequest(http.MethodPost, "/api/v1/ssh-credentials", strings.NewReader("{nope")))
	require.Equal(t, http.StatusBadRequest, r.Code)

	// Fingerprint RuleDraft without a uuid path param → 400.
	fpH := NewFingerprintHandler(service.NewFingerprintReportService(queries, conn))
	r = httptest.NewRecorder()
	fpH.RuleDraft(r, httptest.NewRequest(http.MethodPost, "/api/v1/devices//fingerprint-draft", nil))
	require.Equal(t, http.StatusBadRequest, r.Code)

	// Heartbeat ListConfigs with a non-numeric device id → 400.
	hbStore, err := service.OpenHeartbeatStore(filepath.Join(t.TempDir(), "hb.db"))
	require.NoError(t, err)
	t.Cleanup(func() { hbStore.Close() })
	hbH := NewHeartbeatHandler(service.NewHeartbeatService(conn, hbStore, &config.Config{}))
	r = httptest.NewRecorder()
	hbH.ListConfigs(r, reqWithBodyParams(http.MethodGet, "/api/v1/devices/abc/heartbeat-configs", "", map[string]string{"id": "abc"}))
	require.Equal(t, http.StatusBadRequest, r.Code)
}

// TestHandler_BadIDBadJSONSweep table-drives the bad-id / bad-JSON /
// bad-pagination 400 branches across every id-taking or body-decoding handler
// family, the branches that never fire through the full-router integration
// tests (chi routes don't match non-numeric {id} patterns there... they DO
// match, but those suites only send valid ids).
func TestHandler_BadIDBadJSONSweep(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)

	auditRepo := service.NewAuditRepository(conn)
	taskH := NewScannerTaskHandler(taskservice.New(queries, conn, nil, false))
	probeH := NewProbeTargetHandler(probetarget.New(queries, nil), queries)
	notifH := NewNotificationHandler(service.NewNotificationService(queries), nil, auditRepo)
	grantH := NewNetworkGrantHandler(conn, nil)
	// The credential handler 503s on a nil cipher BEFORE parsing id/body;
	// give it a real 32-byte cipher so the validation branches are reachable.
	credCipher, err := crypto.NewCipher(make([]byte, crypto.MasterKeyLen))
	require.NoError(t, err)
	credH := NewCredentialHandler(conn, credCipher, nil)
	auditH := NewAuditHandler(service.NewAuditService(conn))
	batchH := NewBatchHandler(service.NewBatchService(conn, auditRepo))
	sysH := NewDeviceSystemHandler(service.NewDeviceSystemService(service.NewDeviceSystemRepository(conn)))
	admH := NewAgentAdminHandler(queries, service.NewAgentTokenService(queries))
	cmdH := NewAgentCommandHandler(queries, service.NewAgentCommandService(queries, false, false), nil)
	sshH, _ := setupSSHCredHandler(t)

	badID := func(method, path string) *http.Request {
		return reqWithBodyParams(method, path, "", map[string]string{"id": "abc"})
	}
	badJSON := func(method, path string) *http.Request {
		return httptest.NewRequest(method, path, strings.NewReader("{nope"))
	}

	cases := []struct {
		name string
		h    func(http.ResponseWriter, *http.Request)
		req  *http.Request
		want int
	}{
		// --- scanner tasks: parseScanID + decode + pagination ---
		{"task get bad id", taskH.GetTask, badID(http.MethodGet, "/x"), 400},
		{"task update bad id", taskH.UpdateTask, badID(http.MethodPut, "/x"), 400},
		{"task delete bad id", taskH.DeleteTask, badID(http.MethodDelete, "/x"), 400},
		{"task trigger bad id", taskH.TriggerTask, badID(http.MethodPost, "/x"), 400},
		{"task cancel bad id", taskH.CancelScanTask, badID(http.MethodPost, "/x"), 400},
		{"task runs bad id", taskH.GetTaskRuns, badID(http.MethodGet, "/x"), 400},
		{"task results bad id", taskH.GetTaskResults, badID(http.MethodGet, "/x"), 400},
		{"task create bad json", taskH.CreateTask, badJSON(http.MethodPost, "/x"), 400},
		{"task list bad pagination", taskH.ListTasks, httptest.NewRequest(http.MethodGet, "/x?limit=zzz", nil), 400},

		// --- probe targets ---
		{"probe get bad id", probeH.GetTarget, badID(http.MethodGet, "/x"), 400},
		{"probe update bad id", probeH.UpdateTarget, badID(http.MethodPut, "/x"), 400},
		{"probe delete bad id", probeH.DeleteTarget, badID(http.MethodDelete, "/x"), 400},
		{"probe trigger bad id", probeH.TriggerTarget, badID(http.MethodPost, "/x"), 400},
		{"probe results bad id", probeH.GetTargetResults, badID(http.MethodGet, "/x"), 400},
		{"probe certificates bad id", probeH.GetTargetCertificates, badID(http.MethodGet, "/x"), 400},
		{"probe create bad json", probeH.CreateTarget, badJSON(http.MethodPost, "/x"), 400},
		{"probe list bad pagination", probeH.ListTargets, httptest.NewRequest(http.MethodGet, "/x?limit=zzz", nil), 400},

		// --- notification channels/rules/logs ---
		{"channel get bad id", notifH.GetChannel, badID(http.MethodGet, "/x"), 400},
		{"channel update bad id", notifH.UpdateChannel, badID(http.MethodPut, "/x"), 400},
		{"channel set-enabled bad id", notifH.SetChannelEnabled, badID(http.MethodPut, "/x"), 400},
		{"channel delete bad id", notifH.DeleteChannel, badID(http.MethodDelete, "/x"), 400},
		{"channel create bad json", notifH.CreateChannel, badJSON(http.MethodPost, "/x"), 400},
		{"notif logs bad pagination", notifH.ListNotificationLogs, httptest.NewRequest(http.MethodGet, "/x?limit=zzz", nil), 400},
		{"notif logs no context", notifH.ListNotificationLogs, httptest.NewRequest(http.MethodGet, "/x", nil), 401},
		{"notif mark-read no context", notifH.MarkAllNotificationLogsRead, httptest.NewRequest(http.MethodPost, "/x", nil), 401},

		// --- network grants ---
		{"grant create bad json", grantH.Create, badJSON(http.MethodPost, "/x"), 400},
		{"grant list bad pagination", grantH.List, httptest.NewRequest(http.MethodGet, "/x?limit=zzz", nil), 400},
		{"grant list-by-user bad id", grantH.ListByUser, badID(http.MethodGet, "/x"), 400},
		{"grant delete bad id", grantH.Delete, badID(http.MethodDelete, "/x"), 400},

		// --- SNMP credentials ---
		{"cred get bad id", credH.Get, badID(http.MethodGet, "/x"), 400},
		{"cred update bad id", credH.Update, badID(http.MethodPut, "/x"), 400},
		{"cred delete bad id", credH.Delete, badID(http.MethodDelete, "/x"), 400},
		{"cred create bad json", credH.Create, badJSON(http.MethodPost, "/x"), 400},

		// --- audit ---
		{"audit list bad pagination", auditH.List, httptest.NewRequest(http.MethodGet, "/x?limit=zzz", nil), 400},

		// --- batch ---
		{"batch del devices bad json", batchH.BatchDeleteDevices, badJSON(http.MethodPost, "/x"), 400},
		{"batch del devices empty ids", batchH.BatchDeleteDevices, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"ids":[]}`)), 400},
		{"batch del devices negative id", batchH.BatchDeleteDevices, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"ids":[-1]}`)), 400},
		{"batch status bad json", batchH.BatchUpdateDeviceStatus, badJSON(http.MethodPost, "/x"), 400},
		{"batch status empty ids", batchH.BatchUpdateDeviceStatus, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"ids":[]}`)), 400},
		{"batch status missing status", batchH.BatchUpdateDeviceStatus, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"ids":[1]}`)), 400},
		{"batch del users bad json", batchH.BatchDeleteUsers, badJSON(http.MethodPost, "/x"), 400},
		{"batch del users empty ids", batchH.BatchDeleteUsers, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"ids":[]}`)), 400},

		// --- device systems ---
		{"system create bad json", sysH.Create, badJSON(http.MethodPost, "/x"), 400},
		{"system list bad device id", sysH.ListByDevice, badID(http.MethodGet, "/x"), 400},
		{"system get bad system id", sysH.Get, reqWithBodyParams(http.MethodGet, "/x", "", map[string]string{"id": "1", "systemId": "abc"}), 400},
		{"system delete bad device id", sysH.Delete, badID(http.MethodDelete, "/x"), 400},

		// --- agent admin tokens ---
		{"token create bad json", admH.Create, badJSON(http.MethodPost, "/x"), 400},
		{"token revoke bad id", admH.Revoke, badID(http.MethodPost, "/x"), 400},
		{"token delete bad id", admH.Delete, badID(http.MethodDelete, "/x"), 400},

		// --- agent command channel ---
		{"cmd create no agent id", cmdH.Create, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"command":"scan"}`)), 400},
		{"cmd create bad json", cmdH.Create, reqWithBodyParams(http.MethodPost, "/x", "{nope", map[string]string{"agentId": "a1"}), 400},
		{"cmd ack bad id", cmdH.Ack, badID(http.MethodPost, "/x"), 400},
		{"cmd complete bad id", cmdH.Complete, badID(http.MethodPost, "/x"), 400},
		{"cmd complete bad json", cmdH.Complete, reqWithBodyParams(http.MethodPost, "/x", "{nope", map[string]string{"id": "1"}), 400},

		// --- SSH credentials ---
		{"ssh get bad id", sshH.Get, badID(http.MethodGet, "/x"), 400},
		{"ssh update bad id", sshH.Update, badID(http.MethodPut, "/x"), 400},
		{"ssh delete bad id", sshH.Delete, badID(http.MethodDelete, "/x"), 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.h(rec, tc.req)
			require.Equal(t, tc.want, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

// TestHandler_AuditFilterAndGrantTail covers the audit List filter-assembly
// branches (user_id/action/resource_type/date_from/date_to/search, valid and
// unparseable dates) and the network-grant Delete not-found path (404 fires
// before the nil resolver would ever be touched).
func TestHandler_AuditFilterAndGrantTail(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	auditH := NewAuditHandler(service.NewAuditService(conn))
	grantH := NewNetworkGrantHandler(conn, nil)

	// Full valid filter → 200; the parse branches all take the success arm.
	rec := httptest.NewRecorder()
	auditH.List(rec, httptest.NewRequest(http.MethodGet,
		"/x?user_id=1&action=login&resource_type=user&date_from=2026-01-01T00:00:00Z&date_to=2026-12-31T23:59:59Z&search=foo", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	// Unparseable dates take the ignore arm (not an error, filter is skipped).
	rec = httptest.NewRecorder()
	auditH.List(rec, httptest.NewRequest(http.MethodGet,
		"/x?user_id=notanumber&date_from=yesterday&date_to=soon", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	// Facets on an empty table → 200 (the svc happy path).
	rec = httptest.NewRecorder()
	auditH.Facets(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	// Grant Delete for an id that doesn't exist → 404 (lookup precedes the
	// resolver Invalidate call, so a nil resolver is never dereferenced).
	rec = httptest.NewRecorder()
	grantH.Delete(rec, reqWithBodyParams(http.MethodDelete, "/x", "", map[string]string{"id": "99999"}))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

// ctxUser wraps a request with the auth-context values the middleware would
// normally inject, so authenticated endpoints can be invoked directly.
func ctxUser(r *http.Request, userID int64, role string) *http.Request {
	ctx := context.WithValue(r.Context(), domain.ContextKeyUserID, userID)
	ctx = context.WithValue(ctx, domain.ContextKeyRole, role)
	return r.WithContext(ctx)
}

// TestUserHandler_ErrorTailMatrix drives the auth/user handler's validation
// and error-mapping branches against a REAL user service (seeded via
// Register/Login): decode failures, missing fields, 401-without-context,
// unknown-user 404s, wrong/same/weak passwords, and the first-run setup 409.
func TestUserHandler_ErrorTailMatrix(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	auditRepo := service.NewAuditRepository(conn)
	strictPolicy := config.PasswordPolicyConfig{MinLength: 24}
	svc := service.NewUserService(conn, "test-secret-key-for-tests-32-bytes!!", time.Hour, strictPolicy)
	h := NewUserHandler(svc, &config.Config{}, auditRepo, nil)

	// Seed one user with a policy-compliant password.
	seeded, err := svc.Register(context.Background(), "round20u", "r20@example.com", "a-long-enough-pass-phrase-42", "viewer")
	require.NoError(t, err)
	uid := seeded.ID

	// Login: malformed body / missing fields / wrong password.
	rw := httptest.NewRecorder()
	h.Login(rw, httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("{nope")))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.Login(rw, httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"round20u"}`)))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.Login(rw, httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"round20u","password":"wrong"}`)))
	require.Equal(t, http.StatusUnauthorized, rw.Code)
	// Login happy path (covers the success tail incl. audit + cookie).
	rw = httptest.NewRecorder()
	h.Login(rw, httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"round20u","password":"a-long-enough-pass-phrase-42"}`)))
	require.Equal(t, http.StatusOK, rw.Code)

	// First-run setup runs exactly once: with a password already set it 409s forever.
	rw = httptest.NewRecorder()
	h.PostSetup(rw, httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(`{"new_password":"whatever-long-enough-1234"}`)))
	require.Equal(t, http.StatusConflict, rw.Code)
	rw = httptest.NewRecorder()
	h.PostSetup(rw, httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader("{nope")))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.PostSetup(rw, httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(`{"new_password":""}`)))
	require.Equal(t, http.StatusBadRequest, rw.Code)

	// Register: decode / missing fields / duplicate username.
	rw = httptest.NewRecorder()
	h.Register(rw, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("{nope")))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.Register(rw, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"username":"x"}`)))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.Register(rw, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"username":"round20u","email":"dup@example.com","password":"a-long-enough-pass-phrase-42"}`)))
	require.Equal(t, http.StatusConflict, rw.Code)

	// Profile: 401 without context, 404 for an unknown user.
	rw = httptest.NewRecorder()
	h.GetProfile(rw, httptest.NewRequest(http.MethodGet, "/profile", nil))
	require.Equal(t, http.StatusUnauthorized, rw.Code)
	rw = httptest.NewRecorder()
	h.GetProfile(rw, ctxUser(httptest.NewRequest(http.MethodGet, "/profile", nil), 99999, "admin"))
	require.Equal(t, http.StatusNotFound, rw.Code)

	// UpdateProfile: 401 / bad json / empty email.
	rw = httptest.NewRecorder()
	h.UpdateProfile(rw, httptest.NewRequest(http.MethodPut, "/profile", nil))
	require.Equal(t, http.StatusUnauthorized, rw.Code)
	rw = httptest.NewRecorder()
	h.UpdateProfile(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader("{nope")), uid, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.UpdateProfile(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(`{"email":""}`)), uid, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code)

	// ChangePassword: 401 / bad json / missing fields / wrong old / same pw /
	// happy path.
	rw = httptest.NewRecorder()
	h.ChangePassword(rw, httptest.NewRequest(http.MethodPut, "/password", nil))
	require.Equal(t, http.StatusUnauthorized, rw.Code)
	rw = httptest.NewRecorder()
	h.ChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/password", strings.NewReader("{nope")), uid, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.ChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/password", strings.NewReader(`{"old_password":"x"}`)), uid, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.ChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/password",
		strings.NewReader(`{"old_password":"totally-wrong","new_password":"another-long-phrase-777"}`)), uid, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code) // incorrect current password
	rw = httptest.NewRecorder()
	h.ChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/password",
		strings.NewReader(`{"old_password":"a-long-enough-pass-phrase-42","new_password":"a-long-enough-pass-phrase-42"}`)), uid, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code) // same password
	rw = httptest.NewRecorder()
	h.ChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/password",
		strings.NewReader(`{"old_password":"a-long-enough-pass-phrase-42","new_password":"rotated-long-phrase-9999"}`)), uid, "viewer"))
	require.Equal(t, http.StatusOK, rw.Code)

	// ForceChangePassword: 401 / bad json / empty / unknown user / weak / same /
	// happy path (mints a fresh token).
	rw = httptest.NewRecorder()
	h.ForceChangePassword(rw, httptest.NewRequest(http.MethodPut, "/force-password", nil))
	require.Equal(t, http.StatusUnauthorized, rw.Code)
	rw = httptest.NewRecorder()
	h.ForceChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/force-password", strings.NewReader("{nope")), uid, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.ForceChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/force-password", strings.NewReader(`{"new_password":""}`)), uid, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.ForceChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/force-password",
		strings.NewReader(`{"new_password":"brand-new-long-phrase-5555"}`)), 99999, "viewer"))
	require.Equal(t, http.StatusNotFound, rw.Code)
	rw = httptest.NewRecorder()
	h.ForceChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/force-password",
		strings.NewReader(`{"new_password":"short"}`)), uid, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code) // too weak for MinLength=24
	rw = httptest.NewRecorder()
	h.ForceChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/force-password",
		strings.NewReader(`{"new_password":"rotated-long-phrase-9999"}`)), uid, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code) // same as current
	rw = httptest.NewRecorder()
	h.ForceChangePassword(rw, ctxUser(httptest.NewRequest(http.MethodPut, "/force-password",
		strings.NewReader(`{"new_password":"forced-rotation-phrase-3333"}`)), uid, "viewer"))
	require.Equal(t, http.StatusOK, rw.Code)
	require.Contains(t, rw.Body.String(), "token")

	// ListUsers: bad pagination.
	rw = httptest.NewRecorder()
	h.ListUsers(rw, httptest.NewRequest(http.MethodGet, "/users?limit=zzz", nil))
	require.Equal(t, http.StatusBadRequest, rw.Code)
}

// TestTOTPHandler_TailBranches covers the 2FA handler's decode/validation
// early returns and the Verify error mapping (not-configured / not-enabled).
func TestTOTPHandler_TailBranches(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	auditRepo := service.NewAuditRepository(conn)
	userSvc := service.NewUserService(conn, "test-secret-key-for-tests-32-bytes!!", time.Hour, config.PasswordPolicyConfig{})
	totpSvc := service.NewTOTPService(conn, auditRepo)
	h := NewTOTPHandler(totpSvc, userSvc, &config.Config{}, auditRepo)

	seeded, err := userSvc.Register(context.Background(), "totpu", "totp@example.com", "Some-Password-1234", "viewer")
	require.NoError(t, err)

	// Enable/Disable decode + field validation.
	rw := httptest.NewRecorder()
	h.Enable(rw, ctxUser(httptest.NewRequest(http.MethodPost, "/enable", strings.NewReader("{nope")), seeded.ID, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.Enable(rw, ctxUser(httptest.NewRequest(http.MethodPost, "/enable", strings.NewReader(`{}`)), seeded.ID, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code) // code required
	rw = httptest.NewRecorder()
	h.Enable(rw, ctxUser(httptest.NewRequest(http.MethodPost, "/enable", strings.NewReader(`{"code":"123456"}`)), seeded.ID, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code) // 2FA not set up yet
	rw = httptest.NewRecorder()
	h.Disable(rw, ctxUser(httptest.NewRequest(http.MethodPost, "/disable", strings.NewReader("{nope")), seeded.ID, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.Disable(rw, ctxUser(httptest.NewRequest(http.MethodPost, "/disable", strings.NewReader(`{}`)), seeded.ID, "viewer"))
	require.Equal(t, http.StatusBadRequest, rw.Code) // password required

	// Status: 401 without context; 200 with.
	rw = httptest.NewRecorder()
	h.Status(rw, httptest.NewRequest(http.MethodGet, "/status", nil))
	require.Equal(t, http.StatusUnauthorized, rw.Code)
	rw = httptest.NewRecorder()
	h.Status(rw, ctxUser(httptest.NewRequest(http.MethodGet, "/status", nil), seeded.ID, "viewer"))
	require.Equal(t, http.StatusOK, rw.Code)

	// Verify: decode / missing fields / unknown user (not configured).
	rw = httptest.NewRecorder()
	h.Verify(rw, httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader("{nope")))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.Verify(rw, httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(`{"user_id":0,"code":""}`)))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.Verify(rw, httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(`{"user_id":99999,"code":"123456"}`)))
	require.Equal(t, http.StatusBadRequest, rw.Code) // 2FA not configured
	// Setup creates a PENDING secret; verify then reports "not enabled".
	rw = httptest.NewRecorder()
	h.Setup(rw, ctxUser(httptest.NewRequest(http.MethodPost, "/setup", nil), seeded.ID, "viewer"))
	require.Equal(t, http.StatusCreated, rw.Code)
	rw = httptest.NewRecorder()
	h.Verify(rw, httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(
		fmt.Sprintf(`{"user_id":%d,"code":"000000"}`, seeded.ID))))
	require.Equal(t, http.StatusBadRequest, rw.Code) // 2FA is not enabled
}

// TestCredAndSSHTailsAndScannerResultEmpty drives the SNMP-credential CRUD
// conflict/not-found/invalidate branches (with a REAL resolver wired so the
// cache-invalidate lines run), the SSH credential duplicate/404 branches, and
// the scanner-result empty-list / not-found / bulk-delete validation branches.
func TestCredAndSSHTailsAndScannerResultEmpty(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)

	cipher, err := crypto.NewCipher(make([]byte, crypto.MasterKeyLen))
	require.NoError(t, err)
	credH := NewCredentialHandler(conn, cipher, credresolver.New(conn, cipher))
	sshH, _ := setupSSHCredHandler(t)
	resH := NewScannerResultHandler(queries, conn, service.NewScannerResultService(queries))

	recPost := func(hh func(http.ResponseWriter, *http.Request), body string) *httptest.ResponseRecorder {
		rw := httptest.NewRecorder()
		hh(rw, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body)))
		return rw
	}

	// SNMP credentials: create two, rename one onto the other's name → 409;
	// validation branches for authPriv; delete happy path (resolver wired).
	rw := recPost(credH.Create, `{"name":"alpha","security_level":"v1v2c","community":"public"}`)
	require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())
	rw = recPost(credH.Create, `{"name":"beta","security_level":"v1v2c","community":"public"}`)
	require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())
	rw = httptest.NewRecorder()
	credH.Update(rw, reqWithBodyParams(http.MethodPut, "/x", `{"name":"alpha","security_level":"v1v2c","community":"public"}`, map[string]string{"id": "2"}))
	require.Equal(t, http.StatusConflict, rw.Code, rw.Body.String()) // name already taken
	rw = recPost(credH.Create, `{"name":"bad1","security_level":"authPriv"}`)
	require.Equal(t, http.StatusBadRequest, rw.Code) // username required for authPriv
	rw = recPost(credH.Create, `{"name":"bad2","security_level":"authPriv","username":"u"}`)
	require.Equal(t, http.StatusBadRequest, rw.Code) // auth_protocol required
	rw = httptest.NewRecorder()
	credH.List(rw, httptest.NewRequest(http.MethodGet, "/x?limit=zzz", nil))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	credH.Get(rw, reqWithBodyParams(http.MethodGet, "/x", "", map[string]string{"id": "999"}))
	require.Equal(t, http.StatusNotFound, rw.Code)
	rw = httptest.NewRecorder()
	credH.Delete(rw, reqWithBodyParams(http.MethodDelete, "/x", "", map[string]string{"id": "2"}))
	require.Equal(t, http.StatusNoContent, rw.Code)

	// SSH credentials: duplicate name → 409; unknown-id update/delete → 404;
	// real update toggling enabled (leave-unchanged secret path).
	rw = recPost(sshH.Create, sshCreateBody)
	require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())
	rw = recPost(sshH.Create, sshCreateBody)
	require.Equal(t, http.StatusConflict, rw.Code, rw.Body.String())
	rw = httptest.NewRecorder()
	sshH.Update(rw, reqWithBodyParams(http.MethodPut, "/x", `{"name":"core-sw","auth_method":"password","enabled":false}`, map[string]string{"id": "999"}))
	require.Equal(t, http.StatusNotFound, rw.Code)
	rw = httptest.NewRecorder()
	sshH.Delete(rw, reqWithBodyParams(http.MethodDelete, "/x", "", map[string]string{"id": "999"}))
	require.Equal(t, http.StatusNotFound, rw.Code)
	rw = httptest.NewRecorder()
	sshH.Update(rw, reqWithBodyParams(http.MethodPut, "/x", `{"name":"core-sw","auth_method":"password","enabled":false}`, map[string]string{"id": "1"}))
	require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
	rw = httptest.NewRecorder()
	sshH.Delete(rw, reqWithBodyParams(http.MethodDelete, "/x", "", map[string]string{"id": "1"}))
	require.Equal(t, http.StatusNoContent, rw.Code)

	// Scanner results on an empty DB: empty lists serialize as [], single
	// unknown run/result → 404, bulk-delete with bad JSON → 400.
	rw = httptest.NewRecorder()
	resH.ListResults(rw, httptest.NewRequest(http.MethodGet, "/x?alive=false", nil))
	require.Equal(t, http.StatusOK, rw.Code)
	require.Contains(t, rw.Body.String(), `"results":[]`)
	rw = httptest.NewRecorder()
	resH.ListRuns(rw, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.Equal(t, http.StatusOK, rw.Code)
	rw = httptest.NewRecorder()
	resH.GetResult(rw, reqWithBodyParams(http.MethodGet, "/x", "", map[string]string{"id": "999"}))
	require.Equal(t, http.StatusNotFound, rw.Code)
	rw = httptest.NewRecorder()
	resH.GetRun(rw, reqWithBodyParams(http.MethodGet, "/x", "", map[string]string{"id": "999"}))
	require.Equal(t, http.StatusNotFound, rw.Code)
	rw = recPost(resH.BulkDeleteResults, "{nope")
	require.Equal(t, http.StatusBadRequest, rw.Code)
}
