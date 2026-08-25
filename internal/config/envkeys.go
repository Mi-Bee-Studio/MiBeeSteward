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
	"reflect"
	"strings"
)

// envKeyMap builds the exact environment-variable-name → koanf-key mapping
// for every leaf key in the Config struct (#331).
//
// Why exact mapping: the legacy transform replaced EVERY underscore in an env
// var with a dot, so any key whose segment contains an underscore was
// unreachable from the environment — MIBEE_AUTH_INITIAL_ADMIN_PASSWORD became
// auth.initial.admin.password instead of auth.initial_admin_password and was
// silently dropped on unmarshal. Word-only keys (server.port) and dot-only
// keys (security.master_key) worked by coincidence. The documented contract
// ("every config key + MIBEE_* env override", docs/en/configuration.md)
// demands the underscore form work for all keys.
//
// The map is derived by reflecting over the Config struct's `koanf` tags —
// the same tags Unmarshal consumes — so it can never drift from the real key
// universe. Dots in a key path and underscores inside a segment both become
// underscores in the env name (auth.initial_admin_password →
// MIBEE_AUTH_INITIAL_ADMIN_PASSWORD), exactly as users type them.
func envKeyMap(prefix string) map[string]string {
	m := map[string]string{}
	var walk func(t reflect.Type, path string)
	walk = func(t reflect.Type, path string) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := f.Tag.Get("koanf")
			if name == "" || name == "-" {
				continue
			}
			if i := strings.IndexByte(name, ','); i >= 0 {
				name = name[:i]
			}
			key := name
			if path != "" {
				key = path + "." + name
			}
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			switch ft.Kind() {
			case reflect.Struct:
				// Structs that carry their own scalar encoding (time.Time has
				// no koanf tags below it) yield no leaves — harmless.
				walk(ft, key)
			default:
				m[prefix+strings.ToUpper(strings.ReplaceAll(key, ".", "_"))] = key
			}
		}
	}
	walk(reflect.TypeOf(Config{}), "")
	return m
}
