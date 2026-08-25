// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package config

import (
	"os"
	"testing"
)

// writeConfigYAML writes a minimal valid YAML (jwt_secret +
// initial_admin_password are required by validation) and returns its path.
func writeConfigYAML(t *testing.T) string {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "cfg-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.WriteString(`server: {port: 8080, host: "0.0.0.0"}
auth:
  jwt_secret: "this-is-definitely-32-chars-long!!"
  initial_admin_password: "from-yaml"
`); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	return tmp.Name()
}

// TestEnvOverride_KeyCategories guards the three env-override shapes (#331):
// word-only keys, dot-separated keys, and keys with underscores INSIDE a
// segment — the last kind silently failed before the exact-map fix because
// the transform split every underscore into a dot.
func TestEnvOverride_KeyCategories(t *testing.T) {
	yamlPath := writeConfigYAML(t)

	cases := []struct {
		name  string
		env   string
		value string
		check func(cfg *Config) bool
	}{
		{
			name:  "word-only key: server.port",
			env:   "MIBEE_SERVER_PORT",
			value: "9090",
			check: func(cfg *Config) bool { return cfg.Server.Port == 9090 },
		},
		{
			name:  "dot-only key: security.master_key",
			env:   "MIBEE_SECURITY_MASTER_KEY",
			value: "hexbytes",
			check: func(cfg *Config) bool { return cfg.Security.MasterKey == "hexbytes" },
		},
		{
			name:  "underscore segment: auth.initial_admin_password",
			env:   "MIBEE_AUTH_INITIAL_ADMIN_PASSWORD",
			value: "from-env",
			check: func(cfg *Config) bool { return cfg.Auth.InitialAdminPassword == "from-env" },
		},
		{
			name:  "underscore segment: auth.jwt_secret",
			env:   "MIBEE_AUTH_JWT_SECRET",
			value: "this-is-definitely-32-chars-long!!",
			check: func(cfg *Config) bool { return cfg.Auth.JWTSecret == "this-is-definitely-32-chars-long!!" },
		},
		{
			name:  "deep underscore key: database.sqlite.path",
			env:   "MIBEE_DATABASE_SQLITE_PATH",
			value: "/tmp/env.db",
			check: func(cfg *Config) bool { return cfg.Database.SQLite.Path == "/tmp/env.db" },
		},
		{
			name:  "three-level underscore key: retention.sweep_interval_hours",
			env:   "MIBEE_RETENTION_SWEEP_INTERVAL_HOURS",
			value: "12",
			check: func(cfg *Config) bool { return cfg.Retention.SweepIntervalHours == 12 },
		},
		{
			name:  "scanner underscore key: scanner.allow_reserved_targets",
			env:   "MIBEE_SCANNER_ALLOW_RESERVED_TARGETS",
			value: "true",
			check: func(cfg *Config) bool { return cfg.Scanner.AllowReservedTargets },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.env, tc.value)
			cfg, err := Load(yamlPath)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !tc.check(cfg) {
				t.Errorf("%s=%s did not take effect", tc.env, tc.value)
			}
		})
	}
}

// TestEnvOverride_BeatsYAML is the exact repro from #331: the YAML sets
// initial_admin_password and the env var must win, not be silently ignored.
func TestEnvOverride_BeatsYAML(t *testing.T) {
	yamlPath := writeConfigYAML(t)
	t.Setenv("MIBEE_AUTH_INITIAL_ADMIN_PASSWORD", "from-env")

	cfg, err := Load(yamlPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.InitialAdminPassword != "from-env" {
		t.Errorf("env override lost: got %q, want %q", cfg.Auth.InitialAdminPassword, "from-env")
	}
}

// TestEnvKeyMap_CoversDocumentedKeys sanity-checks the reflected map itself:
// spot keys from each category are present and map to the right koanf path.
func TestEnvKeyMap_CoversDocumentedKeys(t *testing.T) {
	m := envKeyMap("MIBEE_")
	for _, env := range []string{
		"MIBEE_SERVER_PORT",
		"MIBEE_SECURITY_MASTER_KEY",
		"MIBEE_AUTH_INITIAL_ADMIN_PASSWORD",
		"MIBEE_AUTH_JWT_SECRET",
		"MIBEE_DATABASE_SQLITE_PATH",
		"MIBEE_RETENTION_SWEEP_INTERVAL_HOURS",
		"MIBEE_SCANNER_ALLOW_RESERVED_TARGETS",
	} {
		if _, ok := m[env]; !ok {
			t.Errorf("envKeyMap missing %s", env)
		}
	}
	if m["MIBEE_AUTH_INITIAL_ADMIN_PASSWORD"] != "auth.initial_admin_password" {
		t.Errorf("wrong mapping: %q", m["MIBEE_AUTH_INITIAL_ADMIN_PASSWORD"])
	}
	if len(m) < 100 {
		t.Errorf("envKeyMap suspiciously small: %d keys", len(m))
	}
}

// TestEnvOverride_YAMLStillWorksWhenNoEnv: without env vars the YAML value
// survives (the map must not interfere with the plain YAML path).
func TestEnvOverride_YAMLStillWorksWhenNoEnv(t *testing.T) {
	yamlPath := writeConfigYAML(t)
	cfg, err := Load(yamlPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.InitialAdminPassword != "from-yaml" {
		t.Errorf("yaml value lost: got %q", cfg.Auth.InitialAdminPassword)
	}
}
