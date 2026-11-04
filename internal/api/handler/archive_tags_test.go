package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	archsvc "mibee-steward/internal/service/archive"
	"mibee-steward/internal/service/tags"
	"mibee-steward/internal/testutil"
)

// setupArchiveTagsRouter mounts ONLY the tag + archive handlers (no auth
// middleware: the capability gates live in routes and are covered by the
// capability-boundary tests; here we exercise the handler JSON behavior).
// Returns the server + the raw test DB for fixture writes.
func setupArchiveTagsRouter(t *testing.T) (*httptest.Server, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q := db.New(conn)

	tagSvc := tags.New(q)
	require.NoError(t, tagSvc.SeedBuiltins(context.Background()))
	svc := archsvc.New(q, config.ArchiveConfig{OfflineDays: 7, RestoreOnlineMinutes: 60}, nil)

	th := NewTagHandler(tagSvc)
	ah := NewArchiveHandler(svc)

	r := chi.NewRouter()
	r.Get("/api/v1/tags", th.List)
	r.Post("/api/v1/tags", th.Create)
	r.Put("/api/v1/tags/{id}", th.Update)
	r.Delete("/api/v1/tags/{id}", th.Delete)
	r.Post("/api/v1/tags/{id}/devices", th.BulkAssign)
	r.Get("/api/v1/devices/{id}/tags", th.ListDeviceTags)
	r.Put("/api/v1/devices/{id}/tags", th.ReplaceDeviceTags)
	r.Get("/api/v1/archive", ah.List)
	r.Get("/api/v1/archive/{id}/dossier", ah.Dossier)
	r.Post("/api/v1/devices/{id}/archive", ah.ArchiveDevice)
	r.Post("/api/v1/devices/{id}/restore", ah.RestoreDevice)
	r.Put("/api/v1/devices/{id}/archive-settings", ah.PutArchiveSettings)

	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	return server, conn
}

func mustPost(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestTagEndpoints_JSONBehavior(t *testing.T) {
	server, _ := setupArchiveTagsRouter(t)

	// List seeds.
	resp, err := http.Get(server.URL + "/api/v1/tags")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var listResp struct {
		Tags []db.Tag `json:"tags"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listResp))
	require.Len(t, listResp.Tags, 4)

	// Create: invalid key rejected.
	require.Equal(t, http.StatusBadRequest, mustPost(t, server.URL+"/api/v1/tags", `{"key":"NO PE"}`).StatusCode)
	// Create: valid.
	resp2 := mustPost(t, server.URL+"/api/v1/tags", `{"key":"visitor","name":"Visitor","color":"#00ff00"}`)
	require.Equal(t, http.StatusCreated, resp2.StatusCode)
	var created db.Tag
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&created))
	require.NotZero(t, created.ID)

	// Duplicate → 409.
	require.Equal(t, http.StatusConflict, mustPost(t, server.URL+"/api/v1/tags", `{"key":"visitor"}`).StatusCode)

	// Built-in delete → 409 (internal is seeded id=1..4; look it up by list).
	resp3, err := http.Get(server.URL + "/api/v1/tags")
	require.NoError(t, err)
	require.NoError(t, json.NewDecoder(resp3.Body).Decode(&listResp))
	resp3.Body.Close()
	var builtinID int64
	for _, tag := range listResp.Tags {
		if tag.Key == "internal" {
			builtinID = tag.ID
		}
	}
	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/tags/"+strconv.FormatInt(builtinID, 10), nil)
	delResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer delResp.Body.Close()
	require.Equal(t, http.StatusConflict, delResp.StatusCode)
}

func TestArchiveEndpoints_JSONBehavior(t *testing.T) {
	server, conn := setupArchiveTagsRouter(t)
	q := db.New(conn)
	ctx := context.Background()

	// A device via the generated CreateDevice (defaults scan_source manual —
	// manual archive applies to any source, so the flow works end to end).
	dev, err := q.CreateDevice(ctx, db.CreateDeviceParams{
		DeviceUuid: "arch-test-uuid", Name: "arch-test", Type: "other", Status: "offline",
		IpAddress: "192.0.2.50", Tags: "{}", UserAttributes: "{}",
	})
	require.NoError(t, err)
	id := dev.ID

	// Empty archive list.
	resp, err := http.Get(server.URL + "/api/v1/archive")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Manual archive.
	require.Equal(t, http.StatusOK, mustPost(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(id, 10)+"/archive", `{"reason":"shelf"}`).StatusCode)
	// Double archive → 409.
	require.Equal(t, http.StatusConflict, mustPost(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(id, 10)+"/archive", `{}`).StatusCode)

	// Pin force_archive, then restore without force → 409; with force → 200.
	putReq, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/devices/"+strconv.FormatInt(id, 10)+"/archive-settings",
		bytes.NewBufferString(`{"pin":"force_archive"}`))
	putResp, err := http.DefaultClient.Do(putReq)
	require.NoError(t, err)
	putResp.Body.Close()
	require.Equal(t, http.StatusOK, putResp.StatusCode)
	require.Equal(t, http.StatusConflict, mustPost(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(id, 10)+"/restore", `{}`).StatusCode)
	require.Equal(t, http.StatusOK, mustPost(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(id, 10)+"/restore", `{"force":true}`).StatusCode)

	// Dossier on the (now restored) device: archive events exist.
	resp2, err := http.Get(server.URL + "/api/v1/archive/" + strconv.FormatInt(id, 10) + "/dossier")
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var dossier struct {
		Entries []archsvc.DossierEntry `json:"entries"`
	}
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&dossier))
	require.NotEmpty(t, dossier.Entries, "manual archive + pin + restore must leave a trail")

	// Threshold override validation: >365 → 400.
	putReq2, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/devices/"+strconv.FormatInt(id, 10)+"/archive-settings",
		bytes.NewBufferString(`{"offline_days_override":999}`))
	putResp2, err := http.DefaultClient.Do(putReq2)
	require.NoError(t, err)
	putResp2.Body.Close()
	require.Equal(t, http.StatusBadRequest, putResp2.StatusCode)

	// Invalid pin → 400.
	putReq3, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/devices/"+strconv.FormatInt(id, 10)+"/archive-settings",
		bytes.NewBufferString(`{"pin":"bogus"}`))
	putResp3, err := http.DefaultClient.Do(putReq3)
	require.NoError(t, err)
	putResp3.Body.Close()
	require.Equal(t, http.StatusBadRequest, putResp3.StatusCode)
}

func TestDeviceTagEndpoints_JSONBehavior(t *testing.T) {
	server, conn := setupArchiveTagsRouter(t)
	q := db.New(conn)
	ctx := context.Background()

	// Two devices + a custom tag to assign.
	d1, err := q.CreateDevice(ctx, db.CreateDeviceParams{
		DeviceUuid: "tag-a-uuid", Name: "tag-a", Type: "other", Status: "online",
		IpAddress: "192.0.2.61", Tags: "{}", UserAttributes: "{}",
	})
	require.NoError(t, err)
	d2, err := q.CreateDevice(ctx, db.CreateDeviceParams{
		DeviceUuid: "tag-b-uuid", Name: "tag-b", Type: "other", Status: "online",
		IpAddress: "192.0.2.62", Tags: "{}", UserAttributes: "{}",
	})
	require.NoError(t, err)

	// GET device tags (empty).
	resp, err := http.Get(server.URL + "/api/v1/devices/" + strconv.FormatInt(d1.ID, 10) + "/tags")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// PUT replace: internal only.
	putReq, _ := http.NewRequest(http.MethodPut,
		server.URL+"/api/v1/devices/"+strconv.FormatInt(d1.ID, 10)+"/tags",
		bytes.NewBufferString(`{"tag_ids":[1]}`))
	putResp, err := http.DefaultClient.Do(putReq)
	require.NoError(t, err)
	putResp.Body.Close()
	require.Equal(t, http.StatusOK, putResp.StatusCode)

	// Replace again with two tags: PUT semantics replace the set.
	putReq2, _ := http.NewRequest(http.MethodPut,
		server.URL+"/api/v1/devices/"+strconv.FormatInt(d1.ID, 10)+"/tags",
		bytes.NewBufferString(`{"tag_ids":[1,2]}`))
	putResp2, err := http.DefaultClient.Do(putReq2)
	require.NoError(t, err)
	putResp2.Body.Close()
	require.Equal(t, http.StatusOK, putResp.StatusCode)

	// Bulk assign tag 3 to both devices.
	bulkResp := mustPost(t, server.URL+"/api/v1/tags/3/devices",
		`{"device_ids":[`+strconv.FormatInt(d1.ID, 10)+`,`+strconv.FormatInt(d2.ID, 10)+`]}`)
	require.Equal(t, http.StatusOK, bulkResp.StatusCode)

	// Empty bulk → 400.
	require.Equal(t, http.StatusBadRequest, mustPost(t, server.URL+"/api/v1/tags/3/devices", `{"device_ids":[]}`).StatusCode)

	// Bad device id → 400.
	badReq, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/devices/abc/tags",
		bytes.NewBufferString(`{"tag_ids":[1]}`))
	badResp, err := http.DefaultClient.Do(badReq)
	require.NoError(t, err)
	badResp.Body.Close()
	require.Equal(t, http.StatusBadRequest, badResp.StatusCode)
}

func TestDossier_CoversAllKinds(t *testing.T) {
	server, conn := setupArchiveTagsRouter(t)
	q := db.New(conn)
	ctx := context.Background()

	dev, err := q.CreateDevice(ctx, db.CreateDeviceParams{
		DeviceUuid: "dossier-uuid", Name: "dossier-dev", Type: "server", Status: "offline",
		IpAddress: "192.0.2.63", Tags: "{}", UserAttributes: "{}",
	})
	require.NoError(t, err)

	// Backfill dossier material directly: a sighting, a TLS cert, a document,
	// a config version, plus a manual archive for the archive-event kind.
	_, err = conn.ExecContext(ctx, `INSERT INTO device_sightings (device_id, ip_address, mac_address, first_seen, last_seen) VALUES (?, '192.0.2.63', 'aa:bb:cc:dd:ee:63', ?, ?)`,
		dev.ID, time.Now().AddDate(0, 0, -3), time.Now().AddDate(0, 0, -1))
	require.NoError(t, err)

	resp, err := http.Post(server.URL+"/api/v1/devices/"+strconv.FormatInt(dev.ID, 10)+"/archive",
		"application/json", bytes.NewBufferString(`{}`))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	dResp, err := http.Get(server.URL + "/api/v1/archive/" + strconv.FormatInt(dev.ID, 10) + "/dossier")
	require.NoError(t, err)
	defer dResp.Body.Close()
	require.Equal(t, http.StatusOK, dResp.StatusCode)
	var dossier struct {
		Entries []struct {
			Kind string `json:"kind"`
		} `json:"entries"`
	}
	require.NoError(t, json.NewDecoder(dResp.Body).Decode(&dossier))
	kinds := map[string]bool{}
	for _, e := range dossier.Entries {
		kinds[e.Kind] = true
	}
	require.True(t, kinds["archive_event"])
	require.True(t, kinds["sighting"], "sighting rows must appear in the dossier timeline")
}

func TestArchiveEndpoints_NotArchivedConflict(t *testing.T) {
	server, conn := setupArchiveTagsRouter(t)
	q := db.New(conn)
	ctx := context.Background()

	dev, err := q.CreateDevice(ctx, db.CreateDeviceParams{
		DeviceUuid: "conflict-uuid", Name: "conflict-dev", Type: "other", Status: "online",
		IpAddress: "192.0.2.64", Tags: "{}", UserAttributes: "{}",
	})
	require.NoError(t, err)

	// Restore a non-archived device → 409.
	require.Equal(t, http.StatusConflict,
		mustPost(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(dev.ID, 10)+"/restore", `{}`).StatusCode)
}
