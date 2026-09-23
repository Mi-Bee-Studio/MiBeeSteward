// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package routes

import (
	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/domain"
)

// registerSNMPCredentialRoutes registers /api/v1/snmp-credentials.
func registerSNMPCredentialRoutes(r chi.Router, credentialHandler *handler.CredentialHandler) {
	r.Route("/api/v1/snmp-credentials", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapCredManage))
		r.Post("/", credentialHandler.Create)
		r.Get("/", credentialHandler.List)
		r.Get("/{id}", credentialHandler.Get)
		r.Put("/{id}", credentialHandler.Update)
		r.Delete("/{id}", credentialHandler.Delete)
	})
}

// registerSSHCredentialRoutes registers /api/v1/ssh-credentials.
func registerSSHCredentialRoutes(r chi.Router, sshCredentialHandler *handler.SSHCredentialHandler) {
	r.Route("/api/v1/ssh-credentials", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapCredManage))
		r.Post("/", sshCredentialHandler.Create)
		r.Get("/", sshCredentialHandler.List)
		r.Get("/{id}", sshCredentialHandler.Get)
		r.Put("/{id}", sshCredentialHandler.Update)
		r.Delete("/{id}", sshCredentialHandler.Delete)
	})
}
