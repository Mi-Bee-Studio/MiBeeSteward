// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package routes

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// openapiExtraRoutes are non-/api routes that ARE part of the documented
// public surface. Everything else outside /api (SPA catch-all, demo-mode
// routes) is excluded from the contract. (/health lives under /api/v1 and is
// covered by the /api prefix rule.)
var openapiExtraRoutes = map[string]bool{
	"/metrics": true,
	"/sd":      true,
}

// openapiMethods is the method set of the documented contract. chi's metrics
// Mount also registers CONNECT/HEAD/OPTIONS/TRACE on /metrics, those are
// transport-level, not API surface.
var openapiMethods = map[string]bool{
	http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodDelete: true, http.MethodPatch: true,
}

// TestOpenAPIRoutesParity is the #274 contract backstop: every route the real
// router serves must be declared in docs/openapi.yaml (and every declared
// path must exist in the router). Path parity only, request/response bodies
// are reviewed by hand; this test catches the "route added, spec forgotten"
// drift class, which is the one that silently breaks generated clients.
//
// On mismatch the test prints the full live route list so updating the YAML
// is a copy-paste, not an archaeology dig.
func TestOpenAPIRoutesParity(t *testing.T) {
	conn := scopeTestDB(t, false)
	router, heartbeatSvc, shutdown := NewRouter(conn, newTestConfig())
	require.NotNil(t, router)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })
	chiRouter, ok := router.(chi.Routes)
	require.True(t, ok, "NewRouter must return a chi router for route walking")

	live := map[string]bool{}
	require.NoError(t, chi.Walk(chiRouter, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !openapiMethods[method] {
			return nil
		}
		norm := strings.TrimRight(route, "/")
		if norm == "" {
			norm = "/"
		}
		// The auth handler mounts its subrouter with a wildcard segment
		// (`/auth/*/login`); the served URL is `/auth/login`.
		norm = strings.ReplaceAll(norm, "/*/", "/")
		// /metrics is Mount-ed, which registers every method on it; the
		// contract surface is the GET exposition only.
		if norm == "/metrics" && method != http.MethodGet {
			return nil
		}
		if !strings.HasPrefix(norm, "/api") && !openapiExtraRoutes[norm] {
			return nil
		}
		live[method+" "+norm] = true
		return nil
	}))
	require.NotEmpty(t, live)

	spec, err := loadOpenAPISpec()
	require.NoError(t, err, "docs/openapi.yaml must parse")

	declared := map[string]bool{}
	for path, item := range spec.Paths {
		norm := strings.TrimRight(path, "/")
		if norm == "" {
			norm = "/"
		}
		// Spec paths are relative to the /api/v1 server base (docs/openapi.yaml
		// servers.url); /metrics and /sd live at the root. Compare full paths.
		if norm != "/metrics" && norm != "/sd" {
			norm = "/api/v1" + norm
		}
		for _, m := range []string{"get", "put", "post", "delete", "patch"} {
			if itemMap, ok := item.(map[string]interface{}); ok && itemMap[m] != nil {
				declared[strings.ToUpper(m)+" "+norm] = true
			}
		}
	}
	var missingInSpec, staleInSpec []string
	for k := range live {
		if !declared[k] {
			missingInSpec = append(missingInSpec, k)
		}
	}
	for k := range declared {
		if !live[k] {
			staleInSpec = append(staleInSpec, k)
		}
	}
	sort.Strings(missingInSpec)
	sort.Strings(staleInSpec)

	if len(missingInSpec) > 0 || len(staleInSpec) > 0 {
		var all []string
		for k := range live {
			all = append(all, k)
		}
		sort.Strings(all)
		fmt.Fprintln(os.Stderr, "=== LIVE ROUTES (update docs/openapi.yaml to match) ===")
		for _, k := range all {
			fmt.Fprintf(os.Stderr, "%s\n", k)
		}
	}
	require.Empty(t, missingInSpec, "routes served by the router but missing from docs/openapi.yaml (live list printed to stderr)")
	require.Empty(t, staleInSpec, "paths declared in docs/openapi.yaml that the router does not serve")
}

// openapiSpec is the minimal shape this test needs from docs/openapi.yaml.
type openapiSpec struct {
	Paths map[string]interface{} `yaml:"paths"`
}

func loadOpenAPISpec() (*openapiSpec, error) {
	// internal/api/routes → repo root/docs/openapi.yaml
	path := filepath.Join("..", "..", "..", "docs", "openapi.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read docs/openapi.yaml: %w", err)
	}
	var spec openapiSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("parse docs/openapi.yaml: %w", err)
	}
	return &spec, nil
}
