// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// portOf extracts a test server's port.
func portOf(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	p, err := strconv.Atoi(u.Port())
	require.NoError(t, err)
	return p
}

// TestHTTPProbe_FetchOne drives the per-URL fetch seam directly against a
// loopback server: a titled page with headers yields structured evidence
// (status/server/powered_by/title, empty keys pruned), and a dead port
// yields nothing without panicking.
func TestHTTPProbe_FetchOne(t *testing.T) {
	p := NewHTTPProbe()
	client := &http.Client{Timeout: 2 * time.Second}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.25")
		w.Header().Set("X-Powered-By", "PHP/8.3")
		_, _ = w.Write([]byte("<html><head><title>NAS Admin</title></head><body>x</body></html>"))
	}))
	t.Cleanup(srv.Close)

	ev := p.fetchOne(context.Background(), client, "http", "127.0.0.1", portOf(t, srv))
	require.NotNil(t, ev, "loopback fetch must produce evidence")
	require.Equal(t, "200 OK", ev.RawData["status"])
	require.Equal(t, "nginx/1.25", ev.RawData["server"])
	require.Equal(t, "PHP/8.3", ev.RawData["powered_by"])
	require.Equal(t, "NAS Admin", ev.RawData["title"])

	// Dead port: no evidence, no panic.
	dead := p.fetchOne(context.Background(), client, "http", "127.0.0.1", 1)
	require.Nil(t, dead)

	// Header-less bare 200: after the empty-key prune the signal sits at the
	// two-field floor (status + url) and still reports.
	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() { bare.Close() })
	ev = p.fetchOne(context.Background(), client, "http", "127.0.0.1", portOf(t, bare))
	require.NotNil(t, ev)
	require.Equal(t, "200 OK", ev.RawData["status"])
	require.NotContains(t, ev.RawData, "server", "absent headers must be pruned from the evidence")
}
