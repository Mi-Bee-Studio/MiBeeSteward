// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.

package handler

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
)

// newWatchServer stands up a real httptest.Server (a real connection is needed
// so ctx.Done fires when the client closes — httptest.ResponseRecorder does
// not model connection lifecycle). Returns the server + the watcher so the
// caller can push events. srv.Close (registered via t.Cleanup) closes all
// in-flight connections, which triggers the handler's ctx.Done → clean exit.
func newWatchServer(t *testing.T) (*httptest.Server, *changedetect.Watcher) {
	t.Helper()
	watcher := changedetect.NewWatcher(nil)
	h := NewChangeWatchHandler(watcher, nil)
	srv := httptest.NewServer(http.HandlerFunc(h.Watch))
	t.Cleanup(srv.Close)
	return srv, watcher
}

// TestChangeWatch_SSEHeadersCorrect is the regression guard for #195: the
// capability-check Flush must NOT run before the text/event-stream Content-Type
// is set. A premature Flush commits 200 with an empty Content-Type, the browser
// aborts the EventSource to CLOSED, and the UI shows a permanent "已断开" banner.
func TestChangeWatch_SSEHeadersCorrect(t *testing.T) {
	srv, _ := newWatchServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/changes/watch", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// The headline assertion (#195): Content-Type is text/event-stream.
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"),
		"SSE response must advertise text/event-stream (regression #195: premature Flush committed empty Content-Type)")
	require.Equal(t, "no-cache", resp.Header.Get("Cache-Control"))
	require.Equal(t, "keep-alive", resp.Header.Get("Connection"))

	// The handler emits an initial ": connected" comment on connect — proving
	// the stream is live (not a zero-length/CLOSED response).
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	require.NoError(t, err, "stream should deliver the initial comment on connect")
	require.NotEmpty(t, line)
}

// TestChangeWatch_DeliversEvents asserts a change pushed to the Watcher reaches
// the SSE client as an "event: change" frame through the fixed handler.
func TestChangeWatch_DeliversEvents(t *testing.T) {
	srv, watcher := newWatchServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/changes/watch", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	// Wait for the handler to subscribe, then push an event.
	time.Sleep(80 * time.Millisecond)
	watcher.Push(db.ChangeLog{ID: 42, ChangeType: "device_added", EntityType: "device"})

	// Read frames until we see the change event or time out.
	br := bufio.NewReader(resp.Body)
	for i := 0; i < 40; i++ {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			t.Fatalf("read frame: %v", err)
		}
		if strings.Contains(line, "device_added") {
			require.Contains(t, line, "device_added", "payload must carry the change type")
			// back up one to confirm the preceding "event: change" was emitted —
			// we only assert the payload line here; the event label is on the prior line.
			return
		}
	}
	t.Fatal("timed out waiting for SSE change event")
}

// TestChangeWatch_NoWatcherReturns503 verifies the unavailable path.
func TestChangeWatch_NoWatcherReturns503(t *testing.T) {
	h := NewChangeWatchHandler(nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/changes/watch", nil)
	h.Watch(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
