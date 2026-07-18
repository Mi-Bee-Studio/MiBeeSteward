// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package agent

import (
	"net"
	"net/http"
	"time"
)

// newCenterClient builds an *http.Client tuned for the agent→center link.
//
// The default http.Client relies on http.DefaultTransport's keep-alive pool,
// which keeps idle connections open indefinitely (well, for IdleConnTimeout).
// When the center restarts (deploy, crash, OOM), those pooled connections
// become half-open: the agent's socket is ESTABLISHED but the center's end no
// longer exists. The NEXT request that reuses such a connection writes bytes
// into a dead socket and blocks on the response read forever — Go's
// http.Client.Timeout does NOT reliably interrupt a stuck persistConn.Read
// (observed: goroutine 49 parked in net/http.(*persistConn).Read for 6+ minutes
// after a center restart, freezing the command poller).
//
// Fixes applied here:
//   - IdleConnTimeout: aggressively reap idle connections (10s) so a stale
//     pool entry is dropped before it can be reused.
//   - DialContext with a bounded dial timeout so a new connection to a down
//     center fails fast instead of hanging on the OS SYN retry backoff.
//   - DisableKeepAlives is intentionally FALSE — keep-alive is fine for the
//     normal case (rapid polls); the IdleConnTimeout handles the stale case.
//   - ExpectContinueTimeout: short, consistent with Go defaults.
//   - The returned client still has a per-request Timeout as a hard ceiling
//     (passed in by the caller) for the rare case where the server accepts the
//     connection but never finishes responding.
func newCenterClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}
