// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import "mibee-steward/internal/service/scannerv2"

// DefaultHandlers returns the standard set of ServiceHandlers, ready to
// register into a scannerv2.Registry. Each handler maps 1:1 to a service name
// emitted by a classifier in package classify.
func DefaultHandlers() []scannerv2.ServiceHandler {
	handlers := []scannerv2.ServiceHandler{
		SSHHandler{},
		HTTPHandler{},
		PrometheusHandler{},
		NodeExporterHandler{},
		RTSPHandler{},
		ONVIFHandler{},
		SNMPHandler{},
		CameraHandler{},
	}
	// Server-class + TLS-wrapped handlers are data-driven (one type per family,
	// registered once per service name) — see handler/services.go and
	// handler/tls_collect.go. (#158)
	handlers = append(handlers, newServerHandlers()...)
	handlers = append(handlers, newTLSCollectHandlers()...)
	return handlers
}
