// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// FenceTarget selects which object the route's {id} names, so the network
// lookup knows which table to walk to reach a device row.
type FenceTarget string

const (
	// FenceTargetDevice: {id} IS the device id (devices, systems, documents,
	// per-device heartbeat-config creation routes).
	FenceTargetDevice FenceTarget = "device"
	// FenceTargetHeartbeatConfig: {id} is a heartbeat_configs id (the
	// /heartbeat-configs/{id} CRUD routes carry the config, not the device).
	FenceTargetHeartbeatConfig FenceTarget = "heartbeat-config"
)

// fenceLookups maps a target to the SQL that resolves the route id to the
// owning device's network agent binding. Each returns (agentID, ok).
var fenceLookups = map[FenceTarget]string{
	FenceTargetDevice: `
		SELECT n.agent_id FROM devices d
		JOIN networks n ON d.network_id = n.id
		WHERE d.id = ?`,
	FenceTargetHeartbeatConfig: `
		SELECT n.agent_id FROM heartbeat_configs hc
		JOIN devices d ON hc.device_id = d.id
		JOIN networks n ON d.network_id = n.id
		WHERE hc.id = ?`,
}

// RejectRemoteNetworkWrite fences mutating routes against devices that live
// in a network managed by a reporting agent or a federated peer center
// (#379): networks.agent_id non-empty. Such devices are mirrors — every hand
// edit would be overwritten by the next report wave, so writes are rejected
// with 403 regardless of the caller's RBAC role (origin is the wall, local
// admin included). Non-existent ids fall through to the handler's 404; a
// NULL/unset network is locally managed and passes.
func RejectRemoteNetworkWrite(db *sql.DB) func(http.Handler) http.Handler {
	return RejectRemoteNetworkWriteFor(FenceTargetDevice, db)
}

// RejectRemoteNetworkWriteFor is the target-selecting variant for routes
// whose {id} param names something other than the device itself.
func RejectRemoteNetworkWriteFor(target FenceTarget, db *sql.DB) func(http.Handler) http.Handler {
	lookup := fenceLookups[target]
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			idStr := chi.URLParam(r, "id")
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil || id <= 0 {
				next.ServeHTTP(w, r) // malformed id → handler 400/404
				return
			}
			var agentID sql.NullString
			err = db.QueryRowContext(r.Context(), lookup, id).Scan(&agentID)
			if err != nil || !agentID.Valid || agentID.String == "" {
				next.ServeHTTP(w, r) // unknown id / locally-managed network
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden: device is managed by network origin '` +
				strings.ReplaceAll(agentID.String, "'", "") + `' (reporting agent or federated peer) and is read-only"}`))
		})
	}
}

// RemoteManagedDeviceIDs returns the subset of ids whose device row sits in
// an agent-managed network - the batch-route guard. A non-empty result
// rejects the whole batch (all-or-nothing, like every other validation).
func RemoteManagedDeviceIDs(ctx context.Context, db *sql.DB, ids []int64) ([]int64, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := db.QueryContext(ctx, `
		SELECT d.id FROM devices d
		JOIN networks n ON d.network_id = n.id
		WHERE n.agent_id IS NOT NULL AND n.agent_id != ''
		  AND d.id IN (`+placeholders+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}
