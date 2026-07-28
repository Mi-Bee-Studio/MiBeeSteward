package handler_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"mibee-steward/internal/domain"
)

// --- Notification Channel Tests ---

func TestNotificationChannel_CRUD(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Create webhook channel
	createBody := `{"name":"Slack Webhook","type":"webhook","config":{"url":"https://hooks.slack.com/test"},"enabled":true}`
	resp := authPost(t, server.URL+"/api/v1/notification/channels", token, createBody)
	require.Equal(t, 201, resp.StatusCode)

	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	require.Equal(t, "Slack Webhook", created["name"])
	require.Equal(t, "webhook", created["type"])
	require.Equal(t, true, created["enabled"])

	channelID := idToString(created["id"])

	// List channels
	resp = authGet(t, server.URL+"/api/v1/notification/channels", token)
	require.Equal(t, 200, resp.StatusCode)

	var list map[string]interface{}
	decodeJSON(t, resp, &list)
	channels, ok := list["channels"].([]interface{})
	require.True(t, ok)
	require.Len(t, channels, 1)
	require.Equal(t, float64(1), list["total"])

	// Get channel by ID
	resp = authGet(t, server.URL+"/api/v1/notification/channels/"+channelID, token)
	require.Equal(t, 200, resp.StatusCode)

	var fetched map[string]interface{}
	decodeJSON(t, resp, &fetched)
	require.Equal(t, "Slack Webhook", fetched["name"])

	// Update channel
	updateBody := `{"name":"Updated Webhook"}`
	resp = authPut(t, server.URL+"/api/v1/notification/channels/"+channelID, token, updateBody)
	require.Equal(t, 200, resp.StatusCode)

	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	require.Equal(t, "Updated Webhook", updated["name"])

	// Delete channel
	resp = authDelete(t, server.URL+"/api/v1/notification/channels/"+channelID, token)
	require.Equal(t, 200, resp.StatusCode)

	// Verify deletion
	resp = authGet(t, server.URL+"/api/v1/notification/channels", token)
	require.Equal(t, 200, resp.StatusCode)
	var afterDelete map[string]interface{}
	decodeJSON(t, resp, &afterDelete)
	require.Equal(t, float64(0), afterDelete["total"])
}

func TestNotificationChannel_EmailPasswordMasked(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Create email channel with password
	config := map[string]string{
		"host":     "smtp.example.com",
		"port":     "587",
		"username": "user@example.com",
		"password": "supersecret",
		"from":     "noreply@example.com",
		"to":       "admin@example.com",
	}
	configJSON, _ := json.Marshal(config)
	createBody := map[string]interface{}{
		"name":    "Email Channel",
		"type":    "email",
		"config":  json.RawMessage(configJSON),
		"enabled": true,
	}
	bodyBytes, _ := json.Marshal(createBody)

	resp := authPost(t, server.URL+"/api/v1/notification/channels", token, string(bodyBytes))
	require.Equal(t, 201, resp.StatusCode)

	// Verify response has masked password
	var created map[string]interface{}
	decodeJSON(t, resp, &created)

	configResp, ok := created["config"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "*****", configResp["password"])
	require.Equal(t, "smtp.example.com", configResp["host"])
}

// TestNotificationChannel_SetEnabled exercises the dedicated PATCH toggle
// endpoint. The contract this guards: toggling `enabled` via PATCH must NOT
// rewrite name/type/config — in particular the masked SMTP password must stay
// the real value in the DB, never the `"*****"` mask that would be written if
// someone naively did a GET-then-full-PUT round-trip. This is the data
// corruption #53 was worried about; the dedicated endpoint sidesteps it.
func TestNotificationChannel_SetEnabled(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// --- Webhook channel: toggle should leave config.url untouched ---
	whBody := `{"name":"WH","type":"webhook","config":{"url":"https://hooks.example/x"},"enabled":true}`
	resp := authPost(t, server.URL+"/api/v1/notification/channels", token, whBody)
	require.Equal(t, 201, resp.StatusCode)
	var whCreated map[string]interface{}
	decodeJSON(t, resp, &whCreated)
	whID := idToString(whCreated["id"])

	// Toggle off then back on via PATCH.
	resp = authPatch(t, server.URL+"/api/v1/notification/channels/"+whID, token, `{"enabled":false}`)
	require.Equal(t, 200, resp.StatusCode)
	var off map[string]interface{}
	decodeJSON(t, resp, &off)
	require.Equal(t, false, off["enabled"])
	require.Equal(t, "WH", off["name"], "name must survive a toggle")

	resp = authPatch(t, server.URL+"/api/v1/notification/channels/"+whID, token, `{"enabled":true}`)
	require.Equal(t, 200, resp.StatusCode)
	var back map[string]interface{}
	decodeJSON(t, resp, &back)
	require.Equal(t, true, back["enabled"])

	// DB ground truth: config.url unchanged after two toggles.
	var whConfig string
	err := db.QueryRow("SELECT config FROM notification_channels WHERE id = ?", whCreated["id"]).Scan(&whConfig)
	require.NoError(t, err)
	require.Contains(t, whConfig, "https://hooks.example/x", "webhook url must survive toggles")

	// PATCH a missing channel → 404 (ErrChannelNotFound, not 500).
	resp = authPatch(t, server.URL+"/api/v1/notification/channels/9999", token, `{"enabled":true}`)
	require.Equal(t, 404, resp.StatusCode)

	// --- Email channel: the real corruption-risk path ---
	// A GET-then-PUT full-body round-trip would write the masked password
	// ("*****") back over the real one. The dedicated PATCH must NOT do that.
	emailConfig := map[string]string{
		"host": "smtp.example.com", "port": "587", "username": "u@example.com",
		"password": "supersecret", "from": "n@example.com", "to": "a@example.com",
	}
	cfgJSON, _ := json.Marshal(emailConfig)
	emailBody, _ := json.Marshal(map[string]interface{}{
		"name": "Email", "type": "email", "config": json.RawMessage(cfgJSON), "enabled": true,
	})
	resp = authPost(t, server.URL+"/api/v1/notification/channels", token, string(emailBody))
	require.Equal(t, 201, resp.StatusCode)
	var emCreated map[string]interface{}
	decodeJSON(t, resp, &emCreated)

	// Toggle the email channel off.
	resp = authPatch(t, server.URL+"/api/v1/notification/channels/"+idToString(emCreated["id"]), token, `{"enabled":false}`)
	require.Equal(t, 200, resp.StatusCode)

	// DB ground truth: the REAL password must still be in the DB (not "*****").
	var emConfig string
	err = db.QueryRow("SELECT config FROM notification_channels WHERE id = ?", emCreated["id"]).Scan(&emConfig)
	require.NoError(t, err)
	require.Contains(t, emConfig, "supersecret", "real SMTP password must survive an enabled toggle")
	require.NotContains(t, emConfig, `"*****"`, "masked placeholder must never be written back to the DB")

	// And the API response masks it (defense-in-depth check).
	var toggled map[string]interface{}
	decodeJSON(t, resp, &toggled)
	emRespCfg, ok := toggled["config"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "*****", emRespCfg["password"], "API still masks the password in responses")
}

func TestNotificationChannel_CreateMissingName(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	createBody := `{"type":"webhook","config":{}}`
	resp := authPost(t, server.URL+"/api/v1/notification/channels", token, createBody)
	require.Equal(t, 400, resp.StatusCode)
}

func TestNotificationChannel_CreateInvalidType(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	createBody := `{"name":"Test","type":"invalid","config":{}}`
	resp := authPost(t, server.URL+"/api/v1/notification/channels", token, createBody)
	require.Equal(t, 400, resp.StatusCode)
}

func TestNotificationChannel_NotFound(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	resp := authGet(t, server.URL+"/api/v1/notification/channels/9999", token)
	require.Equal(t, 404, resp.StatusCode)
}

// --- Alert Rule Tests removed: MiBee Steward does not build alerting. ---

// --- Notification Log Tests ---
//
// Note: the "total" field in GET /notification/logs responses is the
// requesting user's UNREAD count (not the total row count) — the header bell
// consumes it for the badge. The tests below assert unread semantics.

func TestNotificationLogs_List(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// List logs (should be empty)
	resp := authGet(t, server.URL+"/api/v1/notification/logs", token)
	require.Equal(t, 200, resp.StatusCode)

	var logs map[string]interface{}
	decodeJSON(t, resp, &logs)
	require.Equal(t, float64(0), logs["total"])
	logList, ok := logs["logs"].([]interface{})
	require.True(t, ok)
	require.Len(t, logList, 0)
}

func TestNotificationLogs_Pagination(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Insert some notification logs directly
	for i := 0; i < 5; i++ {
		_, err := db.Exec(
			"INSERT INTO notification_log (status, payload, error_message) VALUES (?, ?, ?)",
			"sent", `{"subject":"test"}`, "",
		)
		require.NoError(t, err)
	}

	// Default pagination — 5 unread for admin (total == unread count)
	resp := authGet(t, server.URL+"/api/v1/notification/logs", token)
	require.Equal(t, 200, resp.StatusCode)
	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	require.Equal(t, float64(5), result["total"])
	logList, ok := result["logs"].([]interface{})
	require.True(t, ok)
	require.Len(t, logList, 5)
	// Each log carries a per-user is_read flag (all unread here).
	firstLog, ok := logList[0].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, false, firstLog["is_read"])

	// Limit 2 — unread count is still 5 (pagination doesn't change the badge)
	resp = authGet(t, server.URL+"/api/v1/notification/logs?limit=2&offset=0", token)
	require.Equal(t, 200, resp.StatusCode)
	var paginated map[string]interface{}
	decodeJSON(t, resp, &paginated)
	require.Equal(t, float64(5), paginated["total"])
	pagList, ok := paginated["logs"].([]interface{})
	require.True(t, ok)
	require.Len(t, pagList, 2)

	// Offset 3
	resp = authGet(t, server.URL+"/api/v1/notification/logs?limit=2&offset=3", token)
	require.Equal(t, 200, resp.StatusCode)
	var offsetResult map[string]interface{}
	decodeJSON(t, resp, &offsetResult)
	offsetList, ok := offsetResult["logs"].([]interface{})
	require.True(t, ok)
	require.Len(t, offsetList, 2)
}

// TestNotificationLogs_MarkAllRead verifies the bell's core flow: unread count
// reflects new logs, drops to 0 after mark-all-read, and stays 0 on refresh.
func TestNotificationLogs_MarkAllRead(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Insert 3 notification logs
	for i := 0; i < 3; i++ {
		_, err := db.Exec(
			"INSERT INTO notification_log (status, payload, error_message) VALUES (?, ?, ?)",
			"sent", `{"subject":"test"}`, "",
		)
		require.NoError(t, err)
	}

	// GET /logs → unread count = 3, all logs is_read=false
	resp := authGet(t, server.URL+"/api/v1/notification/logs", token)
	require.Equal(t, 200, resp.StatusCode)
	var before map[string]interface{}
	decodeJSON(t, resp, &before)
	require.Equal(t, float64(3), before["total"])

	// POST /logs/read → mark all read
	resp = authPost(t, server.URL+"/api/v1/notification/logs/read", token, "")
	require.Equal(t, 200, resp.StatusCode)
	var markResult map[string]interface{}
	decodeJSON(t, resp, &markResult)
	require.Equal(t, float64(3), markResult["marked"])

	// GET /logs again → unread count = 0, all logs is_read=true
	resp = authGet(t, server.URL+"/api/v1/notification/logs", token)
	require.Equal(t, 200, resp.StatusCode)
	var after map[string]interface{}
	decodeJSON(t, resp, &after)
	require.Equal(t, float64(0), after["total"])
	logList, ok := after["logs"].([]interface{})
	require.True(t, ok)
	require.Len(t, logList, 3) // list still shows all logs, just marked read
	firstLog, ok := logList[0].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, true, firstLog["is_read"])

	// POST /logs/read again → idempotent, 0 newly-marked
	resp = authPost(t, server.URL+"/api/v1/notification/logs/read", token, "")
	require.Equal(t, 200, resp.StatusCode)
	var markResult2 map[string]interface{}
	decodeJSON(t, resp, &markResult2)
	require.Equal(t, float64(0), markResult2["marked"])
}

// TestNotificationLogs_PerUserIsolation verifies each user has an independent
// read water mark — user A marking read does NOT clear user B's badge.
func TestNotificationLogs_PerUserIsolation(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	adminToken := loginAsAdmin(t, server)

	// Create a second (non-admin) user
	hash, err := bcrypt.GenerateFromPassword([]byte("user123"), bcrypt.DefaultCost)
	require.NoError(t, err)
	_, err = db.Exec(
		"INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
		"alice", "alice@test.com", string(hash), "user",
	)
	require.NoError(t, err)
	aliceToken := loginAs(t, server, "alice", "user123")

	// Insert 2 notification logs
	for i := 0; i < 2; i++ {
		_, err := db.Exec(
			"INSERT INTO notification_log (status, payload, error_message) VALUES (?, ?, ?)",
			"sent", `{"subject":"test"}`, "",
		)
		require.NoError(t, err)
	}

	// Both users start with 2 unread
	for _, tok := range []string{adminToken, aliceToken} {
		resp := authGet(t, server.URL+"/api/v1/notification/logs", tok)
		require.Equal(t, 200, resp.StatusCode)
		var r map[string]interface{}
		decodeJSON(t, resp, &r)
		require.Equal(t, float64(2), r["total"], "both users should see 2 unread initially")
	}

	// Admin marks all read
	resp := authPost(t, server.URL+"/api/v1/notification/logs/read", adminToken, "")
	require.Equal(t, 200, resp.StatusCode)

	// Admin now has 0 unread, Alice STILL has 2 (independent water marks)
	resp = authGet(t, server.URL+"/api/v1/notification/logs", adminToken)
	require.Equal(t, 200, resp.StatusCode)
	var adminAfter map[string]interface{}
	decodeJSON(t, resp, &adminAfter)
	require.Equal(t, float64(0), adminAfter["total"], "admin should have 0 unread after marking")

	resp = authGet(t, server.URL+"/api/v1/notification/logs", aliceToken)
	require.Equal(t, 200, resp.StatusCode)
	var aliceAfter map[string]interface{}
	decodeJSON(t, resp, &aliceAfter)
	require.Equal(t, float64(2), aliceAfter["total"], "alice should still have 2 unread (independent water mark)")
}

// TestNotificationLogs_RequireAuthNotAdmin verifies the route was widened from
// RequireAdmin to RequireAuth: a regular (non-admin) user can now read logs
// and mark them read, because the bell renders for every authenticated user.
func TestNotificationLogs_RequireAuthNotAdmin(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	// Create a non-admin user
	hash, err := bcrypt.GenerateFromPassword([]byte("user123"), bcrypt.DefaultCost)
	require.NoError(t, err)
	_, err = db.Exec(
		"INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
		"bob", "bob@test.com", string(hash), "user",
	)
	require.NoError(t, err)
	bobToken := loginAs(t, server, "bob", "user123")

	// Non-admin can GET /logs (would have been 403 under the old RequireAdmin)
	resp := authGet(t, server.URL+"/api/v1/notification/logs", bobToken)
	require.Equal(t, 200, resp.StatusCode)

	// Non-admin can POST /logs/read
	resp = authPost(t, server.URL+"/api/v1/notification/logs/read", bobToken, "")
	require.Equal(t, 200, resp.StatusCode)

	// Unauthenticated is still rejected
	resp, err = server.Client().Get(server.URL + "/api/v1/notification/logs")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 401, resp.StatusCode)
}

// --- Test Channel Endpoint ---

func TestNotificationChannel_TestDispatch(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Create enabled channel
	createBody := `{"name":"Test Channel","type":"webhook","config":{"url":"https://example.com/hook"},"enabled":true}`
	resp := authPost(t, server.URL+"/api/v1/notification/channels", token, createBody)
	require.Equal(t, 201, resp.StatusCode)

	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	channelID := idToString(created["id"])

	// Test channel
	resp = authPost(t, server.URL+"/api/v1/notification/channels/"+channelID+"/test", token, "")
	require.Equal(t, 200, resp.StatusCode)

	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	require.Equal(t, "test notification dispatched", result["message"])
}

func TestNotificationChannel_TestDisabledChannel(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Create disabled channel
	createBody := `{"name":"Disabled Channel","type":"webhook","config":{"url":"https://example.com/hook"},"enabled":false}`
	resp := authPost(t, server.URL+"/api/v1/notification/channels", token, createBody)
	require.Equal(t, 201, resp.StatusCode)

	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	channelID := idToString(created["id"])

	// Test disabled channel — should fail
	resp = authPost(t, server.URL+"/api/v1/notification/channels/"+channelID+"/test", token, "")
	require.Equal(t, 400, resp.StatusCode)
}

func TestNotificationChannel_TestNotFound(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	resp := authPost(t, server.URL+"/api/v1/notification/channels/9999/test", token, "")
	require.Equal(t, 404, resp.StatusCode)
}

// --- Auth Tests ---

func TestNotificationEndpoints_RequireAdmin(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	// Create a regular user
	_, err := db.Exec(
		"INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
		"user", "user@test.com", "$2a$10$dummyhashfortest000000000000000000000000000000000000000", "user",
	)
	require.NoError(t, err)

	// Try accessing notification endpoints without auth
	resp, err := server.Client().Get(server.URL + "/api/v1/notification/channels")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 401, resp.StatusCode)

	resp, err = server.Client().Get(server.URL + "/api/v1/notification/logs")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 401, resp.StatusCode)
}

// --- Domain Validation Tests ---

func TestChannelTypeValidation(t *testing.T) {
	require.Equal(t, domain.ChannelType("webhook"), domain.ChannelTypeWebhook)
	require.Equal(t, domain.ChannelType("email"), domain.ChannelTypeEmail)
}

// --- JSON Decode Error ---

func TestNotificationChannel_InvalidJSON(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	resp := authPost(t, server.URL+"/api/v1/notification/channels", token, "invalid json")
	defer resp.Body.Close()
	require.Equal(t, 400, resp.StatusCode)
}
