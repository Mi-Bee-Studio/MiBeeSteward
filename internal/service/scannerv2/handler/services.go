// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"context"
	"fmt"

	"mibee-steward/internal/service/scannerv2"
)

// This file adds ServiceHandlers for service identities that classifiers emit
// but that previously had NO handler. Without a handler, orchestrator.go skips
// EnrichDevice for these services, so a host whose only detected service was
// (say) mysql or smb ended up with an empty inferred_type → "other".
//
// Each handler marks the device as a "server" (these services — DBs,
// mail, remote-access, directory, file-sharing — all imply a server-class
// host). The classification itself (port/banner → service name) is unchanged;
// this only fills in the missing type-inference step.
//
// Data-driven registration (#158): a SINGLE serverServiceHandler type,
// parameterized by name, replaces ~13 named stub types (MySQLHandler,
// SMTPHandler, VNCHandler, …). The registry matches handlers by Service()
// output, so one value-per-name is all the interface needs — adding a new
// server-class service is now one entry in serverServiceNames, not a new type
// + 4 method stubs.

// serverServiceHandler is the ONE handler for every server-class service. It
// generates a TCP heartbeat on the service port and assigns inferred_type =
// "server". The service name (returned by Service()) is the dispatch key the
// registry uses to match it to a classifier's output.
type serverServiceHandler struct {
	name string
}

func (h serverServiceHandler) Service() string { return h.name }

func (h serverServiceHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return &scannerv2.HeartbeatSpec{
		Method: "tcp",
		Target: fmt.Sprintf("%s:%d", svc.IP, svc.Identity.Port),
	}
}

func (serverServiceHandler) Collect(_ context.Context, _ scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return nil, nil, nil
}

func (serverServiceHandler) EnrichDevice(svc scannerv2.ServiceContext, _ scannerv2.CollectedData) {
	// Presence of a database / mail / remote-access / directory / file-share
	// service strongly implies a server-class host. preserveExisting keeps any
	// stronger signal (e.g. SNMP-classified router, or a camera from RTSP).
	preserveExisting(svc, "inferred_type", "server")
}

// serverServiceNames is the complete list of server-class service names a
// classifier can emit. Each becomes a registered serverServiceHandler. Grouped
// by family (database / mail / remote-access / directory & file-share) to
// mirror how classifiers discover them.
var serverServiceNames = []string{
	// Databases.
	"mysql", "postgresql", "redis", "mongodb", "mssql", "memcached",
	// Mail.
	"smtp", "pop3", "imap",
	// Remote access (VNC/RDP imply a server/host offering GUI access).
	"vnc", "rdp",
	// Directory & file-share.
	"ldap", "smb",
}

// newServerHandlers returns one serverServiceHandler per name in
// serverServiceNames, ready to register.
func newServerHandlers() []scannerv2.ServiceHandler {
	handlers := make([]scannerv2.ServiceHandler, len(serverServiceNames))
	for i, name := range serverServiceNames {
		handlers[i] = serverServiceHandler{name: name}
	}
	return handlers
}
