package handler_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

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

	// Default pagination
	resp := authGet(t, server.URL+"/api/v1/notification/logs", token)
	require.Equal(t, 200, resp.StatusCode)
	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	require.Equal(t, float64(5), result["total"])
	logList, ok := result["logs"].([]interface{})
	require.True(t, ok)
	require.Len(t, logList, 5)

	// Limit 2
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
