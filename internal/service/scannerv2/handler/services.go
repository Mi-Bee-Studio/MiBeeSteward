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
// Each handler below marks the device as a "server" (these services — DBs,
// mail, remote-access, directory, file-sharing — all imply a server-class
// host). The classification itself (port/banner → service name) is unchanged;
// this only fills in the missing type-inference step.

// serverServiceHandler is the shared implementation: a TCP heartbeat on the
// service port + a server type assignment. Embedded by each named handler so
// we don't repeat the 4-method boilerplate per service.
type serverServiceHandler struct {
	name string
}

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

// Per-service handlers. Service() returns the name a classifier emits; the
// registry matches handlers by that name (handler/registry.go).

type MySQLHandler struct{}
type RedisHandler struct{}
type PostgreSQLHandler struct{}
type MongoDBHandler struct{}
type MSSQLHandler struct{}
type MemcachedHandler struct{}

func (MySQLHandler) Service() string      { return "mysql" }
func (RedisHandler) Service() string      { return "redis" }
func (PostgreSQLHandler) Service() string { return "postgresql" }
func (MongoDBHandler) Service() string    { return "mongodb" }
func (MSSQLHandler) Service() string      { return "mssql" }
func (MemcachedHandler) Service() string  { return "memcached" }

func (h MySQLHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "mysql"}.GenerateHeartbeat(svc)
}
func (h MySQLHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h MySQLHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}

func (h RedisHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "redis"}.GenerateHeartbeat(svc)
}
func (h RedisHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h RedisHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}

func (h PostgreSQLHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "postgresql"}.GenerateHeartbeat(svc)
}
func (h PostgreSQLHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h PostgreSQLHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}

func (h MongoDBHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "mongodb"}.GenerateHeartbeat(svc)
}
func (h MongoDBHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h MongoDBHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}

func (h MSSQLHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "mssql"}.GenerateHeartbeat(svc)
}
func (h MSSQLHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h MSSQLHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}

func (h MemcachedHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "memcached"}.GenerateHeartbeat(svc)
}
func (h MemcachedHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h MemcachedHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}

// Mail handlers.
type SMTPHandler struct{}
type POP3Handler struct{}
type IMAPHandler struct{}

func (SMTPHandler) Service() string { return "smtp" }
func (POP3Handler) Service() string { return "pop3" }
func (IMAPHandler) Service() string { return "imap" }

func (h SMTPHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "smtp"}.GenerateHeartbeat(svc)
}
func (h SMTPHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h SMTPHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}
func (h POP3Handler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "pop3"}.GenerateHeartbeat(svc)
}
func (h POP3Handler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h POP3Handler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}
func (h IMAPHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "imap"}.GenerateHeartbeat(svc)
}
func (h IMAPHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h IMAPHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}

// Remote-access handlers (VNC/RDP imply a server/host offering GUI access).
type VNCHandler struct{}
type RDPHandler struct{}

func (VNCHandler) Service() string { return "vnc" }
func (RDPHandler) Service() string { return "rdp" }

func (h VNCHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "vnc"}.GenerateHeartbeat(svc)
}
func (h VNCHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h VNCHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}
func (h RDPHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "rdp"}.GenerateHeartbeat(svc)
}
func (h RDPHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h RDPHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}

// Directory & file-share handlers.
type LDAPHandler struct{}
type SMBHandler struct{}

func (LDAPHandler) Service() string { return "ldap" }
func (SMBHandler) Service() string  { return "smb" }

func (h LDAPHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "ldap"}.GenerateHeartbeat(svc)
}
func (h LDAPHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h LDAPHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}
func (h SMBHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "smb"}.GenerateHeartbeat(svc)
}
func (h SMBHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h SMBHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}

// HTTPS handler — TLSClassifier emits "https" but there was no handler, so a
// host with only TLS web still dropped to "other". Treat like HTTP → server.
type HTTPSHandler struct{}

func (HTTPSHandler) Service() string { return "https" }

func (h HTTPSHandler) GenerateHeartbeat(svc scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return serverServiceHandler{name: "https"}.GenerateHeartbeat(svc)
}
func (h HTTPSHandler) Collect(ctx context.Context, svc scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return serverServiceHandler{}.Collect(ctx, svc)
}
func (h HTTPSHandler) EnrichDevice(svc scannerv2.ServiceContext, d scannerv2.CollectedData) {
	serverServiceHandler{}.EnrichDevice(svc, d)
}
