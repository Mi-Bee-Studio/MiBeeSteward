package handler

import (
	"context"
	"fmt"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/probe"
)

// This file adds TLS-cert-collection handlers for every TLS-wrapped service a
// classifier can identify. Each handler's Collect() performs a full-certificate
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
// Server-type assignment + TCP heartbeat reuse the existing
// serverServiceHandler so we don't diverge from how https/smtps/etc are typed.

// tlsCollectHandler is the shared implementation embedded by every TLS-wrapped
// service handler. The per-service types just delegate to it.
type tlsCollectHandler struct {
	name string // service name, e.g. "https", "ldaps"
}

// collectCerts is the shared body: dial the service port, grab the cert chain,
// wrap it as TLSCertCollected. Returns nil data (and nil error) when the
// identity has no usable port, so the orchestrator skips persistence cleanly.
func (h tlsCollectHandler) collectCerts(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
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

// heartbeat delegates to serverServiceHandler's TCP heartbeat — these are all
// server-class services and the port is alive if the handshake succeeded.
func (h tlsCollectHandler) heartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return &scannerv2.HeartbeatSpec{
		Method: "tcp",
		Target: fmt.Sprintf("%s:%d", svc.IP, svc.Identity.Port),
	}
}

// enrich delegates to the server-type assignment so hosts with only TLS-wrapped
// services still get inferred_type=server.
func (h tlsCollectHandler) enrich(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	preserveExisting(svc, "inferred_type", "server")
}

// ---- Per-service handler types ----
//
// One struct per service name; each implements the 4-method ServiceHandler
// interface by delegating to tlsCollectHandler. Naming follows the service
// strings emitted by the classifiers (see classify/web_tls.go for "https" and
// classify/mail_remote.go's MiscClassifier for the rest).

// HTTPSHandler — emitted by TLSClassifier for any TLS handshake.
type HTTPSHandler struct{ tlsCollectHandler }

func NewHTTPSHandler() HTTPSHandler { return HTTPSHandler{tlsCollectHandler{name: "https"}} }
func (HTTPSHandler) Service() string { return "https" }
func (h HTTPSHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return h.tlsCollectHandler.heartbeat(svc)
}
func (h HTTPSHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return h.tlsCollectHandler.collectCerts(ctx, svc)
}
func (h HTTPSHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	h.tlsCollectHandler.enrich(svc, d)
}

// LDAPSHhandler — MiscClassifier port-shape for 636.
type LDAPSHandler struct{ tlsCollectHandler }

func NewLDAPSHandler() LDAPSHandler { return LDAPSHandler{tlsCollectHandler{name: "ldaps"}} }
func (LDAPSHandler) Service() string { return "ldaps" }
func (h LDAPSHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return h.tlsCollectHandler.heartbeat(svc)
}
func (h LDAPSHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return h.tlsCollectHandler.collectCerts(ctx, svc)
}
func (h LDAPSHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	h.tlsCollectHandler.enrich(svc, d)
}

// SMTPSHhandler — 465.
type SMTPSHandler struct{ tlsCollectHandler }

func NewSMTPSHandler() SMTPSHandler { return SMTPSHandler{tlsCollectHandler{name: "smtps"}} }
func (SMTPSHandler) Service() string { return "smtps" }
func (h SMTPSHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return h.tlsCollectHandler.heartbeat(svc)
}
func (h SMTPSHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return h.tlsCollectHandler.collectCerts(ctx, svc)
}
func (h SMTPSHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	h.tlsCollectHandler.enrich(svc, d)
}

// IMAPSHhandler — 993.
type IMAPSHandler struct{ tlsCollectHandler }

func NewIMAPSHandler() IMAPSHandler { return IMAPSHandler{tlsCollectHandler{name: "imaps"}} }
func (IMAPSHandler) Service() string { return "imaps" }
func (h IMAPSHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return h.tlsCollectHandler.heartbeat(svc)
}
func (h IMAPSHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return h.tlsCollectHandler.collectCerts(ctx, svc)
}
func (h IMAPSHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	h.tlsCollectHandler.enrich(svc, d)
}

// POP3SHhandler — 995.
type POP3SHandler struct{ tlsCollectHandler }

func NewPOP3SHandler() POP3SHandler { return POP3SHandler{tlsCollectHandler{name: "pop3s"}} }
func (POP3SHandler) Service() string { return "pop3s" }
func (h POP3SHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return h.tlsCollectHandler.heartbeat(svc)
}
func (h POP3SHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return h.tlsCollectHandler.collectCerts(ctx, svc)
}
func (h POP3SHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	h.tlsCollectHandler.enrich(svc, d)
}

// FTPSHhandler — 990 (control). ftps-data (989) is rarely used standalone and
// shares the same TLS shape, so it's covered by the same handler mapping
// below.
type FTPSHandler struct{ tlsCollectHandler }

func NewFTPSHandler() FTPSHandler { return FTPSHandler{tlsCollectHandler{name: "ftps"}} }
func (FTPSHandler) Service() string { return "ftps" }
func (h FTPSHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return h.tlsCollectHandler.heartbeat(svc)
}
func (h FTPSHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return h.tlsCollectHandler.collectCerts(ctx, svc)
}
func (h FTPSHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	h.tlsCollectHandler.enrich(svc, d)
}

// IRCSSHandler — 994.
type IRCSSHandler struct{ tlsCollectHandler }

func NewIRCSSHandler() IRCSSHandler { return IRCSSHandler{tlsCollectHandler{name: "ircs"}} }
func (IRCSSHandler) Service() string { return "ircs" }
func (h IRCSSHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return h.tlsCollectHandler.heartbeat(svc)
}
func (h IRCSSHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return h.tlsCollectHandler.collectCerts(ctx, svc)
}
func (h IRCSSHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	h.tlsCollectHandler.enrich(svc, d)
}

// TelnetSSHandler — 992.
type TelnetSSHandler struct{ tlsCollectHandler }

func NewTelnetSSHandler() TelnetSSHandler { return TelnetSSHandler{tlsCollectHandler{name: "telnets"}} }
func (TelnetSSHandler) Service() string { return "telnets" }
func (h TelnetSSHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return h.tlsCollectHandler.heartbeat(svc)
}
func (h TelnetSSHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return h.tlsCollectHandler.collectCerts(ctx, svc)
}
func (h TelnetSSHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	h.tlsCollectHandler.enrich(svc, d)
}
