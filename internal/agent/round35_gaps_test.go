// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCommandPoller_ConstructorDefaults pins the constructor's defaulting:
// a nil logger, a non-positive poll interval, and an invalid network CIDR
// (boundary check disabled with a warning — the poller still runs).
func TestCommandPoller_ConstructorDefaults(t *testing.T) {
	run := func(context.Context, ScanCommand) (string, error) { return "", nil }
	p := NewCommandPoller("http://127.0.0.1:1", "tok", 0, "not-a-cidr", run, nil)
	require.NotNil(t, p)
	require.Equal(t, 60*time.Second, p.pollEvery, "non-positive interval defaults to 60s")
}

// TestCommandPoller_FetchAndAckFailureArms drives the transport failure arms
// through pollOnce against stub centers: a 500 on fetch surfaces as an error,
// and a failing ack on an otherwise valid command logs + continues.
func TestCommandPoller_FetchAndAckFailureArms(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	run := func(context.Context, ScanCommand) (string, error) { return `{"ok":true}`, nil }

	// Center that 500s everything: fetchPending fails (status arm).
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(broken.Close)
	p := NewCommandPoller(broken.URL, "tok", time.Minute, "192.0.2.0/24", run, logger)
	require.NotPanics(t, func() { p.pollOnce(ctx) })

	// Center that serves the command but 500s the ack: the command executes
	// anyway (best-effort) and completes; the ack failure is logged.
	var mu sync.Mutex
	served := false
	ackFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/ack") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/complete") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mu.Lock()
		served = true
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"commands": []map[string]any{
				{"id": 7, "command": "scan", "payload": `{"targets":"192.0.2.0/24"}`},
			},
		})
	}))
	t.Cleanup(ackFail.Close)

	p2 := NewCommandPoller(ackFail.URL, "tok", time.Minute, "192.0.2.0/24", run, logger)
	require.NotPanics(t, func() { p2.pollOnce(ctx) })
	mu.Lock()
	got := served
	mu.Unlock()
	require.True(t, got, "the command must still be served despite ack 500s")
}

// TestCommandPoller_ExecuteInvalidTargetsAndPayload drives the execute
// validation-failure arms: unparseable targets and a broken JSON payload
// complete as failed without invoking the scan callback.
func TestCommandPoller_ExecuteInvalidTargetsAndPayload(t *testing.T) {
	var mu sync.Mutex
	completions := map[int64][2]string{}
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/complete") {
			id, _ := strconv.ParseInt(strings.Split(r.URL.Path, "/")[5], 10, 64)
			var body struct {
				Status string `json:"status"`
				Result string `json:"result"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			completions[id] = [2]string{body.Status, body.Result}
			mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(center.Close)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	called := false
	p := NewCommandPoller(center.URL, "tok", time.Minute, "192.0.2.0/24",
		func(context.Context, ScanCommand) (string, error) {
			called = true
			return "", nil
		}, logger)
	ctx := context.Background()

	// Invalid targets string: fails at parse, completes failed.
	p.execute(ctx, pendingCommand{ID: 11, Command: "scan", Payload: `{"targets":"not-an-ip"}`})
	mu.Lock()
	c11 := completions[11]
	mu.Unlock()
	require.Equal(t, "failed", c11[0], "result=%s", c11[1])
	require.Contains(t, c11[1], "invalid targets")
	require.False(t, called, "invalid targets never reach the scan callback")

	// Broken payload JSON.
	p.execute(ctx, pendingCommand{ID: 12, Command: "scan", Payload: "{not json"})
	mu.Lock()
	c12 := completions[12]
	mu.Unlock()
	require.Equal(t, "failed", c12[0], "result=%s", c12[1])
	require.Contains(t, c12[1], "bad payload")
}
