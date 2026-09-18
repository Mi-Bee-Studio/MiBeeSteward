// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen -generate types,client -package apiclient -o client.gen.go ../../docs/openapi.yaml

// Package apiclient is the generated Go client of the /api/v1 API contract
// (#274). Regenerate with `make gen-api-go` after editing docs/openapi.yaml —
// the committed output is the source of truth for consumers (agents,
// tooling); hand edits are overwritten on the next generation. Only the
// typed ClientWithResponses + models are consumed; this repo's own server
// uses its chi handlers (not the generated server stubs).
package apiclient
