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
	"mibee-steward/internal/service/scannerv2/probe"
)

// This file adds TLS-cert-collection handlers for every TLS-wrapped service a
// classifier can identify. The handler's Collect() performs a full-certificate
// chain grab (leaf + issuers) via probe.CollectCertChain and returns it as a
// TLSCertCollected payload. The orchestrator detects that payload type and
// persists it via Repository.RecordTLSCerts — handlers themselves never touch
// the repository, keeping the dispatch/repo boundary clean.
//
// The cert grab is dispatched ONLY for ports a classifier flagged as TLS, so
// non-TLS ports never suffer an invalid TLS handshake. The default TLS ports
// (443/8443/9443/4443 and the well-known TLS-wrapped service ports) are
// additionally covered by the TLSProbe's evidence-only grab; this handler path
// covers the additional case of TLS-discovered-on-a-non-default-port and the
// full-chain persistence for every case.
//
// Data-driven registration (#158): a SINGLE tlsCollectHandler type,
// parameterized by name, replaces 8 named stub types (HTTPSHandler,
// LDAPSHandler, SMTPSHandler, …). Adding a new TLS-wrapped service is now one
// entry in tlsCollectNames, not a new type + constructor + 4 method stubs.

// tlsCollectHandler is the ONE handler for every TLS-wrapped service. Service()
// returns the name (the dispatch key); Collect grabs the cert chain; heartbeat
// and enrich reuse the server-class behavior.
type tlsCollectHandler struct {
	name string // service name, e.g. "https", "ldaps"
}

func (h tlsCollectHandler) Service() string { return h.name }

// Collect dials the service port, grabs the cert chain, and wraps it as
// TLSCertCollected. Returns nil data (and nil error) when the identity has no
// usable port, so the orchestrator skips persistence cleanly.
func (h tlsCollectHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	port := svc.Identity.Port
	if port <= 0 {
		return nil, nil, nil
	}
	// Reuse the probe's per-attempt timeout when available, else the cert
	// collector's own default (4s).
	timeout := probe.DefaultTLSTimeout()
	records := probe.CollectCertChain(ctx, svc.IP, port, timeout)
	return scannerv2.TLSCertCollected{
		ServiceName: h.name,
		Port:        port,
		Certs:       records,
	}, nil, nil
}

// GenerateHeartbeat delegates to a TCP heartbeat — these are all server-class
// services and the port is alive if the handshake succeeded.
func (h tlsCollectHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return &scannerv2.HeartbeatSpec{
		Method: "tcp",
		Target: fmt.Sprintf("%s:%d", svc.IP, svc.Identity.Port),
	}
}

// EnrichDevice assigns the server type so hosts with only TLS-wrapped services
// still get inferred_type=server.
func (h tlsCollectHandler) EnrichDevice(svc scannerv2.ServiceContext, _ scannerv2.CollectedData) {
	preserveExisting(svc, "inferred_type", "server")
}

// tlsCollectNames is the complete list of TLS-wrapped service names a
// classifier can emit. "https" is emitted by TLSClassifier for any TLS
// handshake; the rest are port-shape matches from MiscClassifier. Naming
// follows the service strings emitted by the classifiers (see
// classify/web_tls.go and classify/mail_remote.go).
var tlsCollectNames = []string{
	"https",
	"ldaps",   // 636
	"smtps",   // 465
	"imaps",   // 993
	"pop3s",   // 995
	"ftps",    // 990 (control); ftps-data (989) shares the same TLS shape.
	"ircs",    // 994
	"telnets", // 992
}

// newTLSCollectHandlers returns one tlsCollectHandler per name in
// tlsCollectNames, ready to register.
func newTLSCollectHandlers() []scannerv2.ServiceHandler {
	handlers := make([]scannerv2.ServiceHandler, len(tlsCollectNames))
	for i, name := range tlsCollectNames {
		handlers[i] = tlsCollectHandler{name: name}
	}
	return handlers
}
