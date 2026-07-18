// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package version holds the build version of the MiBee Steward binary.
//
// The value is injected at build time via -ldflags:
//
//	go build -ldflags "-X mibee-steward/internal/version.Version=v0.1.0"
//
// When built without ldflags (e.g. `go run`), Version stays "dev".
package version

// Version is the build version. Overridden by ldflags at release build time.
var Version = "dev"
