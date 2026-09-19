// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package notification

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWebhookSender_SendStubs: both webhook senders' bare Send() deliberately
// refuse (config is required) — pin the guard so nobody "fixes" it into a
// silently-wrong plain send.
func TestWebhookSender_SendStubs(t *testing.T) {
	res := NewWebhookSender().Send(context.Background(), Payload{})
	require.False(t, res.Success)
	require.Contains(t, res.Error, "SendWithConfig")

	res = NewFormattedWebhookSender("bogus-kind").Send(context.Background(), Payload{})
	require.False(t, res.Success)
	require.Contains(t, res.Error, "SendWithConfig")
}

func TestWebhookSender_SendWithConfig(t *testing.T) {
	var gotBody, gotHeader string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotHeader = r.Header.Get("X-Token")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)

	s := NewWebhookSender()
	payload := Payload{Subject: "device lost", Body: "cam-3 went offline"}

	// Happy path: custom header forwarded, payload marshaled.
	res := s.SendWithConfig(context.Background(), payload, mustJSON(t, map[string]any{
		"url":     up.URL,
		"headers": map[string]string{"X-Token": "secret"},
	}))
	require.True(t, res.Success, res.Error)
	require.Contains(t, gotBody, "device lost")
	require.Equal(t, "secret", gotHeader)

	// Invalid config JSON / missing URL.
	res = s.SendWithConfig(context.Background(), payload, json.RawMessage(`{nope`))
	require.False(t, res.Success)
	require.Contains(t, res.Error, "invalid webhook config")
	res = s.SendWithConfig(context.Background(), payload, mustJSON(t, map[string]any{"url": ""}))
	require.False(t, res.Success)
	require.Contains(t, res.Error, "URL is required")

	// Non-2xx endpoint: surfaced as a failed result.
	rej := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(rej.Close)
	res = s.SendWithConfig(context.Background(), payload, mustJSON(t, map[string]any{"url": rej.URL}))
	require.False(t, res.Success)

	// Unreachable endpoint.
	res = s.SendWithConfig(context.Background(), payload, mustJSON(t, map[string]any{"url": "http://127.0.0.1:1/none"}))
	require.False(t, res.Success)
}

// TestFormattedWebhookSender_UnsupportedKind: an unknown platform kind is a
// PERMANENT error (no retry).
func TestFormattedWebhookSender_UnsupportedKind(t *testing.T) {
	res := NewFormattedWebhookSender("carrier-pigeon").SendWithConfig(
		context.Background(), Payload{}, json.RawMessage(`{}`))
	require.False(t, res.Success)
	require.True(t, res.Permanent)
	require.Contains(t, res.Error, "unsupported formatted-webhook kind")
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
