// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestServerHandlers_AllNamesRegistered verifies every name in
// serverServiceNames produces a registered handler whose Service() returns that
// name. This guards the data-driven registration (#158) against a name list /
// dispatch mismatch.
func TestServerHandlers_AllNamesRegistered(t *testing.T) {
	handlers := newServerHandlers()
	seen := make(map[string]bool, len(handlers))
	for _, h := range handlers {
		name := h.Service()
		require.NotEmpty(t, name, "server handler must have a non-empty service name")
		require.False(t, seen[name], "duplicate server handler for %q", name)
		seen[name] = true

		// Every server handler assigns inferred_type=server and generates a TCP
		// heartbeat — assert the dispatch behavior is consistent across names.
		sh, ok := h.(serverServiceHandler)
		require.True(t, ok, "expected serverServiceHandler for %q", name)
		require.Equal(t, name, sh.name)

		svc := scannerv2.ServiceContext{
			IP:       "10.0.0.1",
			Identity: scannerv2.ServiceIdentity{Port: 3306},
			Device: scannerv2.DeviceRef{
				Fields: map[string]string{}, // pre-init so enrich mutates this map
			},
		}
		hb := sh.GenerateHeartbeat(svc)
		require.NotNil(t, hb)
		require.Equal(t, "tcp", hb.Method)
		require.Equal(t, "10.0.0.1:3306", hb.Target)

		sh.EnrichDevice(svc, nil)
		require.Equal(t, "server", svc.Device.Fields["inferred_type"])
	}
	// Sanity: the canonical set hasn't shrunk (a deletion without updating this
	// count would silently drop a handler).
	require.Len(t, handlers, len(serverServiceNames))
}

// TestTLSCollectHandlers_AllNamesRegistered verifies every name in
// tlsCollectNames produces a registered handler whose Service() returns that
// name. Guards the data-driven registration (#158).
func TestTLSCollectHandlers_AllNamesRegistered(t *testing.T) {
	handlers := newTLSCollectHandlers()
	seen := make(map[string]bool, len(handlers))
	for _, h := range handlers {
		name := h.Service()
		require.NotEmpty(t, name, "TLS handler must have a non-empty service name")
		require.False(t, seen[name], "duplicate TLS handler for %q", name)
		seen[name] = true

		th, ok := h.(tlsCollectHandler)
		require.True(t, ok, "expected tlsCollectHandler for %q", name)
		require.Equal(t, name, th.name)

		// Heartbeat is TCP on the service port; enrich assigns server type.
		svc := scannerv2.ServiceContext{
			IP:       "10.0.0.2",
			Identity: scannerv2.ServiceIdentity{Port: 443},
			Device: scannerv2.DeviceRef{
				Fields: map[string]string{},
			},
		}
		hb := th.GenerateHeartbeat(svc)
		require.NotNil(t, hb)
		require.Equal(t, "tcp", hb.Method)

		th.EnrichDevice(svc, nil)
		require.Equal(t, "server", svc.Device.Fields["inferred_type"])
	}
	require.Len(t, handlers, len(tlsCollectNames))
}

// TestDefaultHandlers_NoServiceNameCollisions asserts no two handlers in the
// default set claim the same Service() name — a collision would silently shadow
// one handler in the registry.
func TestDefaultHandlers_NoServiceNameCollisions(t *testing.T) {
	all := DefaultHandlers()
	seen := make(map[string]bool, len(all))
	for _, h := range all {
		name := h.Service()
		require.False(t, seen[name], "service name %q registered by two handlers", name)
		seen[name] = true
	}
}
