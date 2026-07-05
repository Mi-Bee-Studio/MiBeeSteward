package scannerv2

import "context"

// Repository is the ④ Persistence abstraction. The orchestrator and handlers
// depend only on this interface, never on sqlc types or *sql.DB. The concrete
// SQLite implementation lives in store/sqlite.go (Phase 1); tests use an
// in-memory fake.
//
// All methods are best-effort from the orchestrator's perspective: persistence
// failures are logged but never abort a scan. This keeps a slow/locked SQLite
// from blocking the detection pipeline.
type Repository interface {
	// RecordEvidence persists raw evidence (subject to sampling — see config
	// scanner.persist_raw_evidence). Implementations may no-op when disabled.
	RecordEvidence(ctx context.Context, ev []Evidence) error

	// RecordServices persists the classified service identities for an IP.
	// Replaces the prior set for the IP within the current scan run.
	RecordServices(ctx context.Context, ip string, services []ServiceIdentity) error

	// RecordDevice upserts the enriched device fields.
	RecordDevice(ctx context.Context, ip string, device DeviceRef) error

	// RecordHeartbeats persists heartbeat specs generated for the IP.
	// Implementations reconcile with existing configs (update vs insert).
	RecordHeartbeats(ctx context.Context, ip string, specs []HeartbeatSpec) error
}

// NoopRepository is a Repository that does nothing. It is the default when no
// persistence is wired (e.g. unit tests, ad-hoc CLI scans).
type NoopRepository struct{}

func (NoopRepository) RecordEvidence(context.Context, []Evidence) error                  { return nil }
func (NoopRepository) RecordServices(context.Context, string, []ServiceIdentity) error   { return nil }
func (NoopRepository) RecordDevice(context.Context, string, DeviceRef) error             { return nil }
func (NoopRepository) RecordHeartbeats(context.Context, string, []HeartbeatSpec) error   { return nil }

// Compile-time check that NoopRepository satisfies Repository.
var _ Repository = NoopRepository{}
