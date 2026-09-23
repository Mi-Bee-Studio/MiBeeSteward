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
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/crypto"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service"
	credresolver "mibee-steward/internal/service/scannerv2/credresolver"
)

// parseDurationOrDefault parses a Go duration string, returning def on empty or
// parse error. Used for optional background-loop timing config keys.
func parseDurationOrDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

// routerResidentSourcesOn reports whether any of the discovery sources that
// only yield data when the host IS the gateway are enabled. When true AND
// router_arp is also on, router_arp is redundant (the gateway's own
// arp_cache/dhcp_leases/conntrack cover the same hosts authoritatively, without
// an extra SNMP walk), used to emit the redundancy warning at startup.
func routerResidentSourcesOn(d config.DiscoveryConfig) bool {
	return d.ARPCache.Enabled || d.DHCPLeases.Enabled || d.Conntrack.Enabled
}

// routerCommunity resolves the SNMP community for cross-subnet ARP walks:
// prefer the dedicated router_arp.community, fall back to the global snmp_community.
func routerCommunity(cfg config.ScannerConfig) string {
	if cfg.RouterARP.Community != "" {
		return cfg.RouterARP.Community
	}
	if cfg.SNMPCommunity != "" {
		return cfg.SNMPCommunity
	}
	return "public"
}

// routerTimeout resolves the per-router ARP-walk timeout in seconds (default 4).
func routerTimeout(cfg config.ScannerConfig) int {
	if cfg.RouterARP.Timeout > 0 {
		return cfg.RouterARP.Timeout
	}
	return 4
}

// buildCredentialCipher constructs the AES-GCM cipher + credential resolver
// from security.master_key. Returns (nil, nil) when the key is unset or
// invalid (so the engine + handler gracefully degrade to v1/v2c). Logs the
// reason on failure so the operator can see why v3 is unavailable.
func buildCredentialCipher(dbConn *sql.DB, cfg *config.Config) (*crypto.Cipher, *credresolver.Resolver) {
	if cfg.Security.MasterKey == "" {
		return nil, nil
	}
	if len(cfg.Security.MasterKey) != crypto.MasterKeyLen {
		slog.Error("security.master_key wrong length (must be exactly 32 bytes); SNMPv3 credential storage disabled",
			"length", len(cfg.Security.MasterKey))
		return nil, nil
	}
	c, err := crypto.NewCipher([]byte(cfg.Security.MasterKey))
	if err != nil {
		slog.Error("security.master_key invalid; SNMPv3 credential storage disabled", "error", err)
		return nil, nil
	}
	slog.Info("SNMPv3 credential resolver enabled",
		"master_key_fingerprint", c.KeyFingerprint([]byte(cfg.Security.MasterKey)))
	return c, credresolver.New(dbConn, c)
}

// rdnsTimeout returns the configured rDNS lookup deadline (seconds), default 2.
func rdnsTimeout(cfg config.ScannerConfig) int {
	if cfg.RDNS.Timeout > 0 {
		return cfg.RDNS.Timeout
	}
	return 2
}

// heartbeatDBPathFor derives the heartbeat.db path from the main DB path:
// same directory, filename "heartbeat.db". This keeps the time-series store
// alongside the main database (e.g. ./data/heartbeat.db next to ./data/mibee.db).
func heartbeatDBPathFor(cfg *config.Config) string {
	mainPath := cfg.Database.SQLite.Path
	if mainPath == "" {
		mainPath = "./data/mibee.db"
	}
	return filepath.Join(filepath.Dir(mainPath), "heartbeat.db")
}

// resolveNetworkID upserts the networks row for this instance's configured
// network (config `network.name`/cidr/site) and returns its id. The returned id
// is stamped onto every device this instance discovers (devices.network_id) so
// multiple instances on different LANs can coexist without IP-key collisions.
//
// Empty/missing name resolves to "default" so single-instance deployments still
// tag their devices (network_id non-NULL), which keeps the (ip, network_id)
// composite-unique index deterministic. Returns 0 only on a hard DB error
// (logged; devices then fall back to NULL network_id and the legacy IP path).
func resolveNetworkID(dbConn *sql.DB, cfg *config.Config) int64 {
	name := cfg.Network.Name
	if name == "" {
		name = "default"
	}
	// Upsert by name: update cidr/site if the row exists, else insert.
	res, err := dbConn.Exec(`
		INSERT INTO networks (name, cidr, site)
		VALUES (?, ?, ?)
		ON CONFLICT(name) DO NOTHING`,
		name, cfg.Network.CIDR, cfg.Network.Site)
	if err != nil {
		slog.Error("resolve network id: upsert networks failed; devices will have NULL network_id",
			"name", name, "error", err)
		return 0
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Row already existed, refresh its cidr/site in case the config changed.
		_, _ = dbConn.Exec(`UPDATE networks SET cidr = ?, site = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?`,
			cfg.Network.CIDR, cfg.Network.Site, name)
	}
	var id int64
	if err := dbConn.QueryRow(`SELECT id FROM networks WHERE name = ?`, name).Scan(&id); err != nil {
		slog.Error("resolve network id: lookup failed; devices will have NULL network_id",
			"name", name, "error", err)
		return 0
	}

	// Backfill: tag every pre-existing device that has no network_id with this
	// instance's network. Without this, a rescan of a legacy (network_id NULL)
	// device would create a DUPLICATE row keyed on (ip, <resolved network_id>)
	// instead of updating the original, the (ip, NULL) and (ip, N) composite
	// keys are distinct in the unique index. This is only safe for the
	// single-instance default; a true multi-agent deployment would reconcile via
	// the center, not backfill blindly.
	if res, err := dbConn.Exec(`UPDATE devices SET network_id = ? WHERE network_id IS NULL`, id); err != nil {
		slog.Warn("resolve network id: device backfill failed; legacy devices keep NULL network_id",
			"network_id", id, "error", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("network identity resolved; tagged pre-existing devices", "id", id, "name", name, "cidr", cfg.Network.CIDR, "devices_tagged", n)
		return id
	}

	slog.Info("network identity resolved", "id", id, "name", name, "cidr", cfg.Network.CIDR)
	return id
}

// agentForNetwork returns the agent_id bound to the given network ("" when
// networkID is nil, the network has no agent, or the lookup fails, all of
// which mean "run locally"). Used by the scheduler's ScanFunc dispatcher to
// route agent-managed networks to their scanner.
func agentForNetwork(dbConn *sql.DB, networkID *int64) string {
	if networkID == nil {
		return ""
	}
	var agentID sql.NullString
	if err := dbConn.QueryRow(`SELECT agent_id FROM networks WHERE id = ?`, *networkID).Scan(&agentID); err != nil {
		// Missing row / transient error: fall back to the local scan path.
		slog.Warn("agent dispatch: network lookup failed; running local scan", "network_id", *networkID, "error", err)
		return ""
	}
	return strings.TrimSpace(agentID.String)
}

// dispatchAgentScan enqueues a scan command for an agent-managed network task
// and records a scan_task_runs row so the task's run history reflects the
// dispatch. The row is left "running": the scan itself executes on the agent,
// and the first host-carrying report for this network closes it with real
// stats (agent_report.go backfillAgentRunStats, #390), duration then measures
// the honest end-to-end latency (command poll + scan + report). Backstops: a
// still-running older run of the SAME task is superseded here (an agent that
// never reported hosts), and the scheduler's stale-run sweeper fails runs
// older than 1h. A failed enqueue is recorded as a FAILED run with the reason;
// the failure must be visible in the UI, not just the journal.
func dispatchAgentScan(ctx context.Context, dbConn *sql.DB, queries *db.Queries, agentCmdSvc *service.AgentCommandService, taskID int64, targets string, timeout time.Duration, agentID string, credentialID int64) {
	// Supersede runs of this task a report never closed (agent down, or it
	// only sent empty/heartbeat reports). Bounded lifetime: at most one cron
	// period of "running" before the next dispatch sweeps it.
	if prev, err := queries.ListScanTaskRuns(ctx, db.ListScanTaskRunsParams{
		Column1: taskID, TaskID: taskID, Limit: 10, Offset: 0,
	}); err == nil {
		now := time.Now()
		for _, r := range prev {
			if r.Status != "running" {
				continue
			}
			started := time.Time{}
			if r.StartedAt != nil {
				started = *r.StartedAt
			}
			fin := now
			if uerr := queries.UpdateScanTaskRun(ctx, db.UpdateScanTaskRunParams{
				Status:       "completed",
				DurationMs:   now.Sub(started).Milliseconds(),
				ErrorMessage: "superseded by next dispatch (no host-carrying report arrived)",
				FinishedAt:   &fin,
				ID:           r.ID,
			}); uerr != nil {
				slog.Warn("agent dispatch: supersede previous run failed", "run_id", r.ID, "error", uerr)
			}
		}
	}

	start := time.Now()
	now := time.Now()
	run, runErr := queries.CreateScanTaskRun(ctx, db.CreateScanTaskRunParams{TaskID: taskID, StartedAt: &now})
	if runErr != nil {
		// No run row → still dispatch; the command channel is the primary
		// effect and the agent view shows it.
		slog.Warn("agent dispatch: run row create failed", "task_id", taskID, "error", runErr)
	}
	runCreated := runErr == nil && run.ID != 0
	finishRun := func(status, errMsg string) {
		if !runCreated {
			return
		}
		fin := time.Now()
		if uerr := queries.UpdateScanTaskRun(ctx, db.UpdateScanTaskRunParams{
			Status:       status,
			DurationMs:   fin.Sub(start).Milliseconds(),
			ErrorMessage: errMsg,
			FinishedAt:   &fin,
			ID:           run.ID,
		}); uerr != nil {
			slog.Warn("agent dispatch: run row update failed", "task_id", taskID, "run_id", run.ID, "error", uerr)
		}
	}

	payload := map[string]interface{}{
		"targets": targets,
		"timeout": int(timeout.Seconds()),
	}
	// #241: forward the task's SNMP credential to the agent BY NAME, vault
	// IDs are per-system (the agent resolves the name against its OWN local
	// snmp_credentials store), and the name is non-secret metadata so no
	// master key is needed here. A missing/unresolvable name on the agent
	// degrades to its global community, preserving pre-#241 behavior.
	if credentialID != 0 {
		if name, err := credresolver.GetSNMPCredentialName(ctx, dbConn, credentialID); err == nil && name != "" {
			payload["credential_name"] = name
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			slog.Warn("agent dispatch: credential name lookup failed; scan falls back to the agent community",
				"task_id", taskID, "credential_id", credentialID, "error", err)
		}
	}
	cmd, err := agentCmdSvc.Enqueue(ctx, agentID, "scan", payload)
	if err != nil {
		slog.Error("agent dispatch: enqueue failed", "task_id", taskID, "agent_id", agentID, "targets", targets, "error", err)
		finishRun("failed", err.Error())
		return
	}
	slog.Info("scan task dispatched to agent", "task_id", taskID, "agent_id", agentID, "command_id", cmd.ID, "targets", targets)
	// Success: the run row stays "running" until the agent's report backfills
	// its real stats (or the backstops above fire).
}
