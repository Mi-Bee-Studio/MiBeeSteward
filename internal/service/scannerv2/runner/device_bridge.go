// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/store"
)

// applyDeviceBridge mirrors v1's DeviceManager.CreateOrUpdate: for an alive
// host, create or update the devices row (filling only empty/"unknown" fields
// on update) and — for newly-created devices — seed heartbeat configs derived
// from the report's heartbeats. Returns (isNew, wasUpdated).
//
// The v2 HostReport already carries enriched device fields (set by
// ServiceHandlers) and generated heartbeats, so this function is a thin
// adapter from the in-memory report to the devices/heartbeat_configs tables.
// applyDeviceBridge mirrors v1's DeviceManager.CreateOrUpdate: for an alive
// host, create or update the devices row (filling only empty/"unknown" fields
// on update) and — for newly-created devices — seed heartbeat configs derived
// from the report's heartbeats. Returns (isNew, wasUpdated).
//
// networkID is the per-call origin network (devices.network_id). The local
// scan path passes rn.networkID (the instance's own network); the center's
// ingestion path passes the agent's network resolved from its token, so one
// center runner can merge reports from many networks without per-agent
// construction.
//
// The v2 HostReport already carries enriched device fields (set by
// ServiceHandlers) and generated heartbeats, so this function is a thin
// adapter from the in-memory report to the devices/heartbeat_configs tables.
func (rn *Runner) applyDeviceBridge(ctx context.Context, rep scannerv2.HostReport, networkID sql.NullInt64, agentID string) (bool, bool) {
	inferredType := rep.Device.Fields["inferred_type"]
	// typeSource records HOW inferredType was determined, for confidence display:
	//   "protocol"  — a service handler set it from real protocol evidence
	//                 (SNMP sysObjectID, RTSP/ONVIF banner, mDNS service type,
	//                 node_exporter). Trustworthy — not spoofable by a hostname.
	//   "heuristic" — the hostname/brand keyword table (device_types.yaml) set
	//                 or overrode it. Spoofable: any DHCP client can name itself
	//                 "viomi-…" or "nas-box". The UI marks these as "inferred".
	//   ""          — fell through to the "other" default; unknown/legacy.
	// The source follows the FINAL value, not the original: a handler-set camera
	// overridden to "pc" by isStrongPcSignal is now heuristic-confidence, because
	// the deciding factor was the hostname keyword, not the protocol evidence.
	typeSource := ""
	if inferredType != "" {
		// An agent report may carry the source the agent's own applyDeviceBridge
		// computed (it ran the same engine remotely). Trust it when present so a
		// hostname-guessed type (heuristic) stays marked heuristic across the wire
		// hop — otherwise the center would default it to "protocol" and the UI
		// confidence badge would lie. For the LOCAL scan path no source is carried
		// (handlers set inferred_type directly), so default to "protocol" then.
		typeSource = rep.Device.Fields["inferred_type_source"]
		if typeSource == "" {
			typeSource = "protocol"
		}
	}
	// A service handler may have set a generic "server"/"pc" type from a single
	// open port (ssh, smb, mysql, …). That's a weak signal — routers, NAS, and
	// cameras all run ssh/smb too. If the hostname/vendor carries a STRONGER,
	// device-specific signal (an explicit router/camera/nas/printer/embedded
	// model name), let the heuristic override the generic verdict. We still
	// trust handler-set specialized types (camera/router/switch/…) as-is: those
	// come from SNMP sysObjectID or protocol detection and are authoritative.
	//
	// One exception: a "camera" verdict that came purely from an RTSP/ONVIF
	// port can misfire on devices that expose RTSP for non-camera reasons — a
	// laptop/desktop running a media/dev RTSP server (port 8554), or a NAS using
	// RTSP for media streaming (e.g. 极空间/ZSpace Z4S runs gortsplib for its
	// 极影视 feature, Synology/QNAP expose RTSP-wrapping web UIs). When the host
	// shows a strong PC signal (notebook/laptop hostname or a desktop OS) OR a
	// strong NAS signal (MiniDLNA/ReadyMedia vendor, smb file-sharing service,
	// or a NAS hostname/brand), that beats the port-derived camera guess. Generic
	// server signals do NOT override camera (routers/NVRs also expose RTSP).
	switch inferredType {
	case "camera":
		if isStrongPcSignal(rep) {
			inferredType = "pc"
			typeSource = sourceForType("pc") // overridden by hostname keyword
		} else if isStrongNasSignal(rep) {
			inferredType = "nas"
			typeSource = sourceForType("nas") // overridden by hostname keyword / smb
		}
	case "", "server", "pc":
		if t, src := heuristicDeviceType(rep); t != "" && t != "server" && t != "pc" {
			// Specialized heuristic verdict (router/camera/nas/…) beats the
			// generic handler verdict. Source comes from the matched YAML rule.
			inferredType = t
			typeSource = src
		} else if inferredType == "" {
			// No handler verdict and no specialized heuristic — take whatever
			// the heuristic offers (including "" → falls to "other" below, or a
			// heuristic "server" from ssh+exporter).
			inferredType = t
			if t != "" {
				typeSource = src
			}
		}
	}
	if inferredType == "" {
		inferredType = "other"
		typeSource = "" // unknown / no signal at all
	}
	// Write the RESOLVED type + its source back into Fields so buildScanAttributes
	// persists both into scan_attributes → API → frontend. inferredType may differ
	// from the handler's original Fields["inferred_type"] (the heuristic or an
	// override branch may have changed it), so we must sync the field here.
	rep.Device.Fields["inferred_type"] = inferredType
	rep.Device.Fields["inferred_type_source"] = typeSource
	inferredBrand := rep.Device.Fields["inferred_brand"]
	inferredDescr := rep.Device.Fields["inferred_description"]
	inferredLoc := rep.Device.Fields["inferred_location"]

	// MAC-primary identity: when a MAC is known, match across ALL networks so a
	// device that roams between subnets (or was seen by another instance) stays
	// a single asset. Without a MAC, fall back to (ip, network_id) — same IP on
	// two different networks is two distinct devices. This mirrors the store's
	// RecordDevice lookup so both upsert writers agree on identity.
	//
	// resolveDeviceIdentity also handles device REPLACEMENT: when a MAC matches a
	// device that sits on a DIFFERENT ip than the one being scanned, and that
	// scanned ip is currently held by a different-MAC device, the ip-holder wins
	// (it is the current authority for that network location) and the old
	// MAC-matched row is marked offline. This is the router-swap case: the new
	// router's MAC was first seen on a transient DHCP ip (.100), then the device
	// took over the gateway ip (.1) which a prior router still occupied.
	mac := reportMAC(rep)
	existingID, replacedID, roamed, err := rn.resolveDeviceIdentity(ctx, mac, rep.IP, networkID)

	switch err {
	case sql.ErrNoRows:
		devID, derr := rn.createDevice(ctx, inferredType, inferredBrand, inferredDescr, inferredLoc, rep, mac, networkID)
		if derr != nil {
			rn.logger.Warn("device bridge: create device failed", "ip", rep.IP, "mac", mac, "error", derr)
			return false, false
		}
		// Change detection: a brand-new device is a device_added event.
		rn.recordDeviceAdded(ctx, devID, networkID, agentID)
		// A freshly-discovered alive host starts online; make sure the heartbeat
		// service holds no stale failure state for it before configs are seeded.
		if rn.heartbeat != nil {
			rn.heartbeat.ResetFailures(devID)
		}
		// Seed heartbeat configs (new devices only, matching v1 behavior).
		if rn.heartbeat != nil {
			if len(rep.Heartbeats) > 0 {
				if herr := rn.heartbeat.CreateConfigs(ctx, devID, rep.Heartbeats); herr != nil {
					rn.logger.Warn("device bridge: seed heartbeats failed", "ip", rep.IP, "error", herr)
				}
			} else {
				// No service was identified (no open ports, or ports the classifiers
				// don't recognize). Without a heartbeat config this device would be
				// discovered once and then never probed again — it would show
				// "no heartbeat" forever even though we just proved it's alive.
				// Fall back to an ICMP config so every discovered host gets at least
				// liveness monitoring. The device already has an IP (rep.IP) and was
				// reached by the scan, so ICMP is always a valid probe target.
				if herr := rn.heartbeat.CreateDefaultConfig(ctx, devID, rep.IP); herr != nil {
					rn.logger.Warn("device bridge: seed ICMP fallback heartbeat failed", "ip", rep.IP, "error", herr)
				}
			}
		}
		return true, false

	case nil:
		// Change detection: capture the BEFORE snapshot before any UPDATE
		// mutates the row. Read the full device row (the identity SELECT above
		// only fetched id). In a replacement the before-snapshot is the OLD
		// device's identity — exactly what we want the device_changed diff to
		// record (e.g. name NanoPiR4S → GL-MT3000).
		before := rn.snapshotDevice(ctx, existingID)
		// Evidence stickiness (type only upgrades, never downgrades). A protocol-
		// derived type (SNMP sysObjectID, RTSP/ONVIF) is authoritative and must
		// NOT be reverted to a heuristic/"other" verdict on a later scan where the
		// probe timed out — that re-derivation is the other↔router type-flap root
		// cause. Trust ranking: protocol > heuristic > unknown. Only apply on a
		// normal re-scan (replacedID==0); a device replacement force-overwrites
		// identity (the new device's type wins), so stickiness must not hold there.
		if replacedID == 0 && before != nil {
			inferredType, typeSource = applyTypeStickiness(before, inferredType, typeSource)
			rep.Device.Fields["inferred_type"] = inferredType
			rep.Device.Fields["inferred_type_source"] = typeSource
		}
		// Pick the UPDATE variant: replacement force-overwrites identity fields
		// (name/type/brand/...) because a new physical device took over the ip;
		// a normal re-scan only fills empty/unknown fields (richer earlier scans
		// win over shallower new ones).
		updateSQL := buildExistingUpdate()
		if replacedID != 0 {
			updateSQL = buildReplacementUpdate()
		}
		if _, uerr := rn.dbConn.ExecContext(ctx, updateSQL,
			existingUpdateArgs(existingID, inferredType, inferredBrand, inferredDescr, inferredLoc, rep, mac)...); uerr != nil {
			rn.logger.Warn("device bridge: update device failed", "ip", rep.IP, "mac", mac, "error", uerr)
		}
		// Always set status=online for alive hosts (matches v1). Also refresh
		// last_seen (online freshness) and stamp mac/network when newly resolved
		// (a re-scan may have filled a previously-empty MAC after an ARP walk).
		// In a device-replacement scenario (replacedID != 0) the target is the
		// ip-holder whose OWN mac differs from the scanned one — overwrite it so
		// the row reflects the device that now physically occupies that ip.
		now := time.Now().UTC()
		if replacedID != 0 {
			// Replacement: force-overwrite mac on the ip-holder (it now belongs to
			// the scanned device), and mark the prior mac-matched row offline.
			_, _ = rn.dbConn.ExecContext(ctx, `
				UPDATE devices SET status='online',
				    mac_address = ?,
				    last_seen = COALESCE(last_seen, ?),
				    offline_since=NULL,
				    last_scanned_at = ?, updated_at = ? WHERE id=?`,
				mac, now, now, now, existingID)
			_, _ = rn.dbConn.ExecContext(ctx,
				`UPDATE devices SET status='offline',
				    offline_since = CASE WHEN status != 'offline' THEN ? ELSE offline_since END,
				    updated_at=? WHERE id=?`,
				now, now, replacedID)
			rn.logger.Warn("device bridge: device replaced (router/asset swap detected)",
				"ip", rep.IP, "scanned_mac", mac, "replaced_device_id", replacedID,
				"target_device_id", existingID,
				"action", "ip-holder updated with new mac; prior mac-matched row marked offline")
		} else {
			// Normal re-scan of an existing alive device. When the device ROAMED
			// (same MAC, new free IP — DHCP renewal), relocate ip_address to the
			// scanned IP so the registry reflects its current address. The prior
			// behavior of never relocating left devices stuck on stale IPs (a NAS
			// that renewed its lease showed an IP days out of date). The before
			// snapshot (read at :186) still holds the old IP, so the DiffIdentity
			// check below catches ip_address as a change → emits device_changed,
			// recording the relocation as the identity event it is.
			ipClause := "ip_address = ip_address"
			if roamed {
				ipClause = "ip_address = ?"
			}
			_, err = rn.dbConn.ExecContext(ctx, `
				UPDATE devices SET status='online',
				    `+ipClause+`,
				    mac_address = CASE WHEN ? != '' AND mac_address = '' THEN ? ELSE mac_address END,
				    last_seen = COALESCE(last_seen, ?),
				    offline_since=NULL,
				    last_scanned_at = ?, updated_at = ? WHERE id=?`,
				argsForRoamUpdate(roamed, rep.IP, mac, now, existingID)...)
			if err != nil && roamed {
				// The roam UPDATE can fail the (ip_address, network_id) unique
				// constraint when a mac='' placeholder row occupies the target IP
				// (the device-split scenario). Rather than silently swallowing the
				// error (the prior bug — the roam was lost and the device stayed on
				// its stale IP), evict the placeholder then retry. The placeholder
				// is a mac-less stale discovery at this IP; the real device (with
				// this MAC) is taking over, so removing it is correct.
				rn.logger.Warn("device bridge: roam update failed, evicting ip-holder placeholder and retrying",
					"ip", rep.IP, "device_id", existingID, "error", err)
				if netClause, netArg := networkClause(networkID); netClause != "" {
					_, _ = rn.dbConn.ExecContext(ctx,
						`DELETE FROM devices WHERE ip_address = ? AND `+netClause+` AND mac_address = '' AND id != ?`,
						append([]any{rep.IP}, append(netArg, existingID)...)...)
				}
				_, err = rn.dbConn.ExecContext(ctx, `
					UPDATE devices SET status='online', ip_address = ?,
					    mac_address = CASE WHEN ? != '' AND mac_address = '' THEN ? ELSE mac_address END,
					    last_seen = COALESCE(last_seen, ?),
					    offline_since=NULL,
					    last_scanned_at = ?, updated_at = ? WHERE id=?`,
					rep.IP, mac, mac, now, now, now, existingID)
				if err != nil {
					rn.logger.Warn("device bridge: roam retry failed", "ip", rep.IP, "device_id", existingID, "error", err)
				}
			}
		}
		// Change detection: re-read the AFTER snapshot and apply the TIERED
		// model. Two separate judgments, so liveness and identity never conflate:
		//   (a) device_recovered — a status flip offline→online. This is the
		//       symmetric counterpart of device_lost. It fires ONLY on the
		//       recovery transition (a scan revives a device DetectLost/lease
		//       sweeper had marked offline), NOT on every rescan of a healthy
		//       device (those have before.status==online already).
		//   (b) device_changed — an IDENTITY field changed (name/type/brand/
		//       model/mac/ip). status is deliberately excluded from this gate
		//       (it is a liveness signal, owned by device_lost/recovered); so is
		//       classification-field wobble (open_ports/services/scan_attributes)
		//       which is recorded in before/after_data but doesn't trip the gate.
		// This replaces the old all-fields Diff that fired a device_changed on
		// every status flip — the root cause of the 70k+ noise-row storm.
		changed := false
		if before != nil {
			after := rn.snapshotDevice(ctx, existingID)
			if after != nil {
				// (a) Recovery: offline→online. Emit device_recovered (not
				// device_changed). The before snapshot was captured at :186
				// BEFORE the status UPDATE, so before.Status is the faithful
				// pre-recovery value.
				if before.Status == "offline" && after.Status == "online" {
					var nidPtr *int64
					if networkID.Valid {
						v := networkID.Int64
						nidPtr = &v
					}
					rn.recordDeviceRecovered(ctx, existingID, nidPtr, agentID, before)
					changed = true
				}
				// (b) Identity change: only identity-tier fields gate device_changed.
				if diff := changedetect.DiffIdentity(*before, *after); diff != nil {
					rn.recordDeviceChanged(ctx, existingID, networkID, agentID, *before, *after, diff)
					changed = true
				}
			}
		}
		// Clear the heartbeat service's failure counter for this device: the
		// scan just proved it's alive, so a stale counter from a prior flapping
		// window must not pull it back to offline on the next heartbeat tick.
		if rn.heartbeat != nil {
			rn.heartbeat.ResetFailures(existingID)
			// Backfill heartbeat configs for pre-existing devices that were
			// discovered before the "always seed at least ICMP" fallback existed.
			// These hosts have been scanned repeatedly but never got a config
			// (because no service was identified on any scan), so they show
			// "no heartbeat" forever. Only act when the device has ZERO configs
			// to avoid duplicating configs on devices that already have some.
			if !rn.deviceHasHeartbeatConfig(ctx, existingID) {
				if len(rep.Heartbeats) > 0 {
					if herr := rn.heartbeat.CreateConfigs(ctx, existingID, rep.Heartbeats); herr != nil {
						rn.logger.Warn("device bridge: backfill heartbeats failed", "ip", rep.IP, "error", herr)
					}
				} else {
					if herr := rn.heartbeat.CreateDefaultConfig(ctx, existingID, rep.IP); herr != nil {
						rn.logger.Warn("device bridge: backfill ICMP fallback heartbeat failed", "ip", rep.IP, "error", herr)
					}
				}
			}
		}
		return false, changed

	default:
		rn.logger.Warn("device bridge: lookup failed", "ip", rep.IP, "mac", mac, "error", err)
		return false, false
	}
}

// snapshotDevice reads the full device row for change-detection diffing. Returns
// nil on lookup error (the caller treats nil as "skip diff"). Uses rn.queries
// (sqlc) so the snapshot matches the schema-typed view changedetect expects.
func (rn *Runner) snapshotDevice(ctx context.Context, deviceID int64) *changedetect.DeviceSnapshot {
	d, err := rn.queries.GetDevice(ctx, deviceID)
	if err != nil {
		return nil
	}
	s := changedetect.SnapshotFromDevice(d)
	return &s
}

// networkClause returns a SQL fragment + arg for a network_id condition matching
// the resolveDeviceIdentity pattern: "network_id = ?" when valid, or
// "network_id IS NULL" when not (empty fragment + nil arg means "no constraint").
func networkClause(networkID sql.NullInt64) (string, []any) {
	if networkID.Valid {
		return "network_id = ?", []any{networkID.Int64}
	}
	return "network_id IS NULL", nil
}

// argsForRoamUpdate builds the positional args for the normal-rescan status
// UPDATE. When roamed is true the SQL has an extra `ip_address = ?` clause (the
// scanned IP comes first); otherwise ip_address is left unchanged (the SQL uses
// `ip_address = ip_address` with no placeholder for it).
func argsForRoamUpdate(roamed bool, ip, mac string, now time.Time, existingID int64) []any {
	if roamed {
		// order matches: ip_address=?, mac_address CASE ?/?, last_seen=?, last_scanned_at=?, updated_at=?, id=?
		return []any{ip, mac, mac, now, now, now, existingID}
	}
	// order matches: mac_address CASE ?/?, last_seen=?, last_scanned_at=?, updated_at=?, id=?
	return []any{mac, mac, now, now, now, existingID}
}

// applyTypeStickiness enforces "type only upgrades, never downgrades" against
// the stored verdict, returning the (type, source) to actually persist. Trust
// ranking: protocol (SNMP/RTSP/ONVIF evidence — authoritative) > heuristic
// (hostname keyword — spoofable) > unknown (no signal → "other").
//
// The rule: if the STORED type came from a protocol source, do not let this
// scan's verdict downgrade it. This is what stops a router (protocol-derived via
// SNMP sysObjectID) from flapping back to "other"/"embedded" on the next scan
// where SNMP timed out — the timed-out scan produced only a heuristic or no
// signal, which must not overwrite the authoritative protocol verdict. Upgrades
// (unknown→protocol, heuristic→protocol) and same-tier changes (protocol→
// protocol when SNMP re-identifies differently) are still accepted.
//
// newType/newSource are this scan's freshly-computed verdict (from the merge
// switch in applyDeviceBridge). before is the device's pre-UPDATE snapshot
// (carries the stored scan_attributes with the prior inferred_type_source).
func applyTypeStickiness(before *changedetect.DeviceSnapshot, newType, newSource string) (string, string) {
	stored, err := domain.UnmarshalScanAttributes(before.ScanAttributes)
	if err != nil {
		// Can't read stored source — can't judge stickiness; accept the new verdict.
		return newType, newSource
	}
	storedSource := stored.InferredTypeSource
	// Stickiness only protects a PROTOCOL-derived stored type. A heuristic
	// stored type may be refined by a later heuristic match, and an unknown
	// stored type ("other"/"") should accept any new signal.
	if storedSource != "protocol" {
		return newType, newSource
	}
	// Stored type is protocol-authoritative. If this scan ALSO has protocol
	// evidence (newSource=="protocol"), accept the new verdict (SNMP may have
	// re-identified the device, or a different protocol handler fired) — that's a
	// legitimate same-or-higher-tier change, not a downgrade.
	if newSource == "protocol" {
		return newType, newSource
	}
	// This scan has NO protocol evidence (probe timed out → newSource is heuristic
	// or ""). Preserve the stored protocol type instead of downgrading. This is
	// the core flap fix: a single missed SNMP poll must not erase an authoritative
	// sysObjectID-derived type.
	return stored.InferredType, "protocol"
}

// recordDeviceAdded emits a device_added event (after_data = the new row). The
// snapshot is read back after createDevice so after_data reflects the persisted
// state, not just the in-memory report.
func (rn *Runner) recordDeviceAdded(ctx context.Context, deviceID int64, networkID sql.NullInt64, agentID string) {
	if rn.changeRecorder == nil {
		return
	}
	var after *changedetect.DeviceSnapshot
	if s := rn.snapshotDevice(ctx, deviceID); s != nil {
		after = s
	}
	var nidPtr *int64
	if networkID.Valid {
		v := networkID.Int64
		nidPtr = &v
	}
	rn.changeRecorder.Record(ctx, changedetect.ChangeEvent{
		ChangeType: changedetect.ChangeTypeDeviceAdded,
		EntityType: changedetect.EntityTypeDevice,
		DeviceID:   deviceID,
		NetworkID:  nidPtr,
		AgentID:    agentID,
		Before:     nil, // added has no before
		After:      after,
	})
}

// recordDeviceChanged emits a device_changed event with before_data + after_data
// both as full DeviceSnapshot JSON (consistent with device_added/device_lost).
// The field-level diff is logged at debug level for operator insight but is NOT
// stored as after_data — storing the diff map there previously produced a
// confusing after_data where scan_attributes was a [old,new] string array
// rather than a snapshot object, and it diverged from the added/lost shape.
// Consumers wanting the delta derive it by diffing before_data vs after_data.
func (rn *Runner) recordDeviceChanged(ctx context.Context, deviceID int64, networkID sql.NullInt64, agentID string, before, after changedetect.DeviceSnapshot, diff map[string][2]string) {
	if rn.changeRecorder == nil {
		return
	}
	var nidPtr *int64
	if networkID.Valid {
		v := networkID.Int64
		nidPtr = &v
	}
	if rn.logger.Enabled(ctx, slog.LevelDebug) {
		fields := make([]any, 0, len(diff)*2)
		for k, v := range diff {
			fields = append(fields, k+"_old", v[0], k+"_new", v[1])
		}
		rn.logger.Debug("device bridge: device_changed", fields...)
	}
	rn.changeRecorder.Record(ctx, changedetect.ChangeEvent{
		ChangeType: changedetect.ChangeTypeDeviceChanged,
		EntityType: changedetect.EntityTypeDevice,
		DeviceID:   deviceID,
		NetworkID:  nidPtr,
		AgentID:    agentID,
		Before:     before,
		After:      after,
	})
}

// resolveDeviceIdentity decides which existing devices row a scan should update,
// or whether a new row must be created. It returns:
//   - targetID: the devices.id to update (valid when err == nil)
//   - replacedID: id of a row superseded by a device replacement (0 when none)
//   - roamed: true when the MAC-matched device moved to a NEW free IP (DHCP
//     roaming). The caller must relocate the row's ip_address to the scanned ip
//     so the registry reflects the device's current address (the prior behavior
//     of NOT relocating left devices stuck on stale IPs — a real-world bug where
//     a NAS that renewed its DHCP lease showed an IP days out of date).
//   - err: sql.ErrNoRows means "create a new row".
func (rn *Runner) resolveDeviceIdentity(ctx context.Context, mac, ip string, networkID sql.NullInt64) (targetID int64, replacedID int64, roamed bool, err error) {
	if mac == "" {
		// No MAC → identity is (ip, network_id).
		if networkID.Valid {
			err = rn.dbConn.QueryRowContext(ctx,
				`SELECT id FROM devices WHERE ip_address = ? AND network_id = ? LIMIT 1`,
				ip, networkID.Int64).Scan(&targetID)
		} else {
			err = rn.dbConn.QueryRowContext(ctx,
				`SELECT id FROM devices WHERE ip_address = ? AND network_id IS NULL LIMIT 1`,
				ip).Scan(&targetID)
		}
		return targetID, 0, false, err
	}

	// MAC present → global identity lookup.
	err = rn.dbConn.QueryRowContext(ctx,
		`SELECT id FROM devices WHERE mac_address = ? LIMIT 1`, mac).Scan(&targetID)
	if err == sql.ErrNoRows {
		// MAC not seen before. Fall back to (ip, network_id) with empty mac so a
		// device first seen MAC-less gets its mac filled on this scan.
		if networkID.Valid {
			err = rn.dbConn.QueryRowContext(ctx,
				`SELECT id FROM devices WHERE ip_address = ? AND network_id = ? AND mac_address = '' LIMIT 1`,
				ip, networkID.Int64).Scan(&targetID)
		} else {
			err = rn.dbConn.QueryRowContext(ctx,
				`SELECT id FROM devices WHERE ip_address = ? AND network_id IS NULL AND mac_address = '' LIMIT 1`,
				ip).Scan(&targetID)
		}
		return targetID, 0, false, err
	}
	if err != nil {
		return 0, 0, false, err
	}

	// MAC matched a row. Check whether it sits on the scanned ip; if so, this is
	// the normal update path (no replacement).
	var macRowIP string
	var macRowMAC string
	if qerr := rn.dbConn.QueryRowContext(ctx,
		`SELECT ip_address, mac_address FROM devices WHERE id = ?`, targetID).Scan(&macRowIP, &macRowMAC); qerr != nil {
		// Failing to read the row's ip is unexpected; proceed with the plain match.
		return targetID, 0, false, nil
	}
	if macRowIP == ip {
		return targetID, 0, false, nil // same ip — normal update, nothing replaced.
	}

	// MAC matched a device on a DIFFERENT ip than the one being scanned. Check
	// whether the scanned ip is held by another device with its own different
	// mac: that signals a device replacement (the new device took over an ip a
	// prior device occupied).
	var ipHolderID int64
	var ipHolderMAC string
	var ipLookErr error
	if networkID.Valid {
		ipLookErr = rn.dbConn.QueryRowContext(ctx,
			`SELECT id, mac_address FROM devices WHERE ip_address = ? AND network_id = ? LIMIT 1`,
			ip, networkID.Int64).Scan(&ipHolderID, &ipHolderMAC)
	} else {
		ipLookErr = rn.dbConn.QueryRowContext(ctx,
			`SELECT id, mac_address FROM devices WHERE ip_address = ? AND network_id IS NULL LIMIT 1`,
			ip).Scan(&ipHolderID, &ipHolderMAC)
	}
	if ipLookErr == sql.ErrNoRows {
		// Scanned ip is free → roaming: the MAC-matched device moved to a new IP
		// (DHCP renewal/re-lease). Keep it as one asset (targetID), but signal
		// roamed=true so the caller relocates ip_address to the scanned ip. The
		// old behavior of NOT relocating left devices stuck on stale IPs.
		return targetID, 0, true, nil
	}
	if ipLookErr != nil {
		// Lookup error → don't speculate; fall back to the plain MAC match.
		return targetID, 0, false, nil
	}
	// Replacement requires the ip-holder to have its OWN mac differing from the
	// scanned one. An empty-mac ip-holder is a MAC-less placeholder (rule 2):
	// leave it to be filled, do not treat as a replacement conflict.
	if ipHolderMAC == "" || ipHolderMAC == mac {
		return targetID, 0, false, nil
	}
	// Device replacement: the ip-holder becomes the target, the MAC-matched row
	// (the prior asset now sitting on a stale ip) is superseded.
	return ipHolderID, targetID, false, nil
}

// reportMAC extracts and canonicalizes the MAC from a HostReport. It checks the
// device Fields first (handler-enriched), then falls back to mac-kind evidence
// (ARP/router-ARP probe output). Returns "" when no MAC was observed.
func reportMAC(rep scannerv2.HostReport) string {
	if m := store.NormalizeMAC(rep.Device.Fields["mac"]); m != "" {
		return m
	}
	for _, e := range rep.Evidence {
		if e.Kind == "mac" {
			if m := store.NormalizeMAC(e.RawData["mac"]); m != "" {
				return m
			}
		}
	}
	return ""
}

// deviceHasHeartbeatConfig reports whether the device already has any row in
// heartbeat_configs. Used by the existing-device branch to decide whether to
// backfill a config: only seed when zero exist, so we never duplicate.
func (rn *Runner) deviceHasHeartbeatConfig(ctx context.Context, deviceID int64) bool {
	var n int
	err := rn.dbConn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM heartbeat_configs WHERE device_id = ?`, deviceID).Scan(&n)
	if err != nil {
		// On query error, assume it has configs so we don't risk duplicating.
		rn.logger.Warn("device bridge: heartbeat_configs count failed", "device_id", deviceID, "error", err)
		return true
	}
	return n > 0
}

// deviceDisplayName picks the value stored in devices.name (the primary display
// field shown in lists, not the separate scan_attributes.hostname). Priority:
// the report's node_hostname/sys_name Fields (set early by the orchestrator from
// TLS-cert CN / mDNS / rDNS), THEN the fully-merged scan_attributes.Hostname
// (which buildScanAttributes enriches further with SNMP sysName + evidence
// hostnames that may arrive after the Fields were set), finally the IP.
//
// The merged-attributes fallback is the fix for the case where a scan collects a
// hostname via SNMP/mDNS but doesn't surface it in Device.Fields (different
// probes populate different stores): without it, devices.name degenerates to the
// IP even though scan_attributes.hostname carries the real name. See issue #19
// follow-up (the "62 scan looked more complete than 63" report — root cause was
// devices.name showing IP while hostname lived only in scan_attributes).
func deviceDisplayName(rep scannerv2.HostReport) string {
	if h := rep.Device.Fields["node_hostname"]; h != "" {
		return h
	}
	if h := rep.Device.Fields["sys_name"]; h != "" {
		return h
	}
	if h := buildScanAttributes(rep).Hostname; h != "" {
		return h
	}
	return rep.IP
}

// createDevice inserts a new device row derived from the report. networkID is
// the per-call origin network (the agent's network on the center ingestion
// path, the instance's own network on the local scan path).
func (rn *Runner) createDevice(ctx context.Context, devType, brand, descr, location string, rep scannerv2.HostReport, mac string, networkID sql.NullInt64) (int64, error) {
	name := deviceDisplayName(rep)
	if devType == "" {
		devType = "other"
	}
	ports, services := deviceScanInfoJSON(rep)
	promURL := rep.Device.Fields["prometheus_url"]
	neURL := rep.Device.Fields["node_exporter_url"]
	tags := buildDeviceTags(devType, brand, rep)
	scanAttrs := marshalScanAttributes(buildScanAttributes(rep))
	now := time.Now().UTC()
	res, err := rn.dbConn.ExecContext(ctx, `
		INSERT INTO devices (device_uuid, name, type, brand, ip_address, mac_address,
		                     status, scan_source, description, location,
		                     open_ports, detected_services, prometheus_url, node_exporter_url,
		                     scan_attributes, network_id, first_seen, last_seen,
		                     tags, last_scan_rtt_ms, last_scanned_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?,
		        'online', 'scanner_v2', ?, ?,
		        ?, ?, ?, ?,
		        ?, ?, ?, ?,
		        ?, ?, ?, ?, ?)`,
		uuid.NewString(), name, devType, brand, rep.IP, mac,
		descr, location,
		ports, services, promURL, neURL,
		scanAttrs, networkID, now, now,
		tags, rep.RTTMs, now, now, now)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// buildExistingUpdate returns the static UPDATE statement for an existing
// device. The positional args are assembled separately in existingUpdateArgs.
//
// scan_attributes uses json_patch (not a blind overwrite) so a SHALLOW scan
// can't erase fields a DEEPER earlier scan (or passive discovery) collected:
// json_patch(old, new) keeps old's keys that new omits. Because every field on
// ScanAttributes is `omitempty`, a scan that didn't collect (say) a hostname
// emits a JSON object WITHOUT a hostname key, and the patch preserves the prior
// value. Slice fields (open_ports/detected_services) are still whole-replaced
// when present — they reflect "what THIS scan saw open", not a union across
// scans (a port that closed should drop off). Issue #20.
func buildExistingUpdate() string {
	return `
		UPDATE devices SET
		    name = CASE WHEN (name = '' OR name = ip_address) THEN ? ELSE name END,
		    type = CASE WHEN (type = '' OR type = 'unknown' OR type = 'other') AND ? != '' THEN ? ELSE type END,
		    brand = CASE WHEN (brand = '' OR brand = 'unknown') AND ? != '' THEN ? ELSE brand END,
		    description = CASE WHEN (description = '' OR description = 'unknown') AND ? != '' THEN ? ELSE description END,
		    location = CASE WHEN (location = '' OR location = 'unknown') AND ? != '' THEN ? ELSE location END,
		    open_ports = ?,
		    detected_services = ?,
		    prometheus_url = CASE WHEN ? != '' THEN ? ELSE prometheus_url END,
		    node_exporter_url = CASE WHEN ? != '' THEN ? ELSE node_exporter_url END,
		    scan_attributes = json_patch(scan_attributes, ?),
		    last_scan_rtt_ms = ?,
		    last_scanned_at = ?,
		    updated_at = ?
		WHERE id = ?`
}

// buildReplacementUpdate returns the UPDATE for the device-REPLACEMENT case (a
// different physical device now occupies this ip). Unlike buildExistingUpdate it
// FORCE-OVERWRITES name/type/brand/description/location — the CASE "only fill
// empty/unknown" guards that protect a re-scan from clobbering a richer earlier
// scan would be WRONG here: this is a brand-new device, so its identity fields
// must fully replace the prior device's. The before/after change-detection diff
// captures the old→new values as a device_changed event (that is where the
// historical "what it was" lives), so the device row itself always reflects the
// current truth.
//
// Shares the SAME positional arg order as buildExistingUpdate, so it reuses
// existingUpdateArgs.
func buildReplacementUpdate() string {
	return `
		UPDATE devices SET
		    name = ?,
		    type = CASE WHEN ? != '' THEN ? ELSE type END,
		    brand = CASE WHEN ? != '' THEN ? ELSE brand END,
		    description = CASE WHEN ? != '' THEN ? ELSE description END,
		    location = CASE WHEN ? != '' THEN ? ELSE location END,
		    open_ports = ?,
		    detected_services = ?,
		    prometheus_url = CASE WHEN ? != '' THEN ? ELSE prometheus_url END,
		    node_exporter_url = CASE WHEN ? != '' THEN ? ELSE node_exporter_url END,
		    scan_attributes = json_patch(scan_attributes, ?),
		    last_scan_rtt_ms = ?,
		    last_scanned_at = ?,
		    updated_at = ?
		WHERE id = ?`
}

// existingUpdateArgs builds the positional args matching buildExistingUpdate's
// placeholder order. (MAC/network_id/last_seen are stamped in a separate UPDATE
// in applyDeviceBridge so the identity fields update on every scan, not just
// when the CASE-when-empty conditions in this statement happen to fire.)
//
// The SAME arg order also matches buildReplacementUpdate — both statements share
// the placeholder layout for the columns they have in common.
func existingUpdateArgs(id int64, inferredType, brand, descr, location string, rep scannerv2.HostReport, _ string) []any {
	ports, services := deviceScanInfoJSON(rep)
	promURL := rep.Device.Fields["prometheus_url"]
	neURL := rep.Device.Fields["node_exporter_url"]
	scanAttrs := marshalScanAttributes(buildScanAttributes(rep))
	now := time.Now().UTC()
	return []any{
		deviceDisplayName(rep), inferredType, inferredType,
		brand, brand,
		descr, descr,
		location, location,
		ports, services,
		promURL, promURL,
		neURL, neURL,
		scanAttrs,
		rep.RTTMs, now, now, id,
	}
}

// deviceScanInfoJSON returns the open_ports + detected_services JSON for the
// devices row.
//
// Format contract (must match the device detail page's parser, which casts
// each element to {port, name?,/service?}):
//   - open_ports:        [{ "port": int, "service": string }]
//   - detected_services: [{ "port": int, "name": string, "protocol": string }]
//
// The previous implementation emitted a bare int array ([80,554,8000]) and a
// bare string array (["camera","onvif","rtsp"]). The frontend's
// parseJsonArray(... as Array<{port,name,protocol}>) then read svc.port as
// undefined for every element, so the Scan Info panel rendered nothing — the
// scan had enriched the device but the user couldn't see it on the web.
func deviceScanInfoJSON(rep scannerv2.HostReport) (string, string) {
	// Both arrays are derived from the SAME deduped source as scan_attributes
	// (serviceArrays): open_ports is deduped-by-port, detected_services is
	// deduped-by-(port,name) with the richest version kept. Reusing that source
	// here keeps the two storage locations (devices.detected_services and
	// scan_attributes.detected_services) consistent and prevents the unbounded
	// duplication that happened when this path appended every raw
	// ServiceIdentity without dedup (port 80 appeared 6× on one test-env host).
	openPorts, svcs := serviceArrays(rep)

	type portEntry struct {
		Port    int    `json:"port"`
		Service string `json:"service,omitempty"`
	}
	portEntries := make([]portEntry, 0, len(openPorts))
	for _, p := range openPorts {
		portEntries = append(portEntries, portEntry{Port: p.Port, Service: p.Service})
	}
	portsJSON := "[]"
	if b, err := json.Marshal(portEntries); err == nil {
		portsJSON = string(b)
	}

	type svcEntry struct {
		Port     int    `json:"port"`
		Name     string `json:"name"`
		Protocol string `json:"protocol,omitempty"`
	}
	svcEntries := make([]svcEntry, 0, len(svcs))
	for _, s := range svcs {
		svcEntries = append(svcEntries, svcEntry{
			Port:     s.Port,
			Name:     s.Name,
			Protocol: s.Protocol,
		})
	}
	svcJSON := "[]"
	if b, err := json.Marshal(svcEntries); err == nil {
		svcJSON = string(b)
	}
	return portsJSON, svcJSON
}

// buildDeviceTags constructs a JSON tag array from type + brand + services.
func buildDeviceTags(devType, brand string, rep scannerv2.HostReport) string {
	tags := map[string]bool{devType: true}
	if brand != "" {
		tags[brand] = true
	}
	for _, s := range rep.Services {
		tags[s.Service] = true
	}
	out := make([]string, 0, len(tags))
	for t := range tags {
		if t != "" {
			out = append(out, t)
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// heuristicDeviceType is the last-resort type inference run in the device
// bridge when no ServiceHandler set inferred_type, or to upgrade a generic
// handler verdict ("server"/"pc"). It is a thin wrapper over matchDeviceType:
// the keyword/port tables live in device_types.yaml (data, not code) and the
// matching engine is the generic priority matcher in device_type_rules.go. Add
// device signatures by editing the YAML, not this function. Returns (type,
// source) where source is the confidence label from the matched YAML rule
// ("heuristic" for all table rules). ("", "") when no hint matches.
func heuristicDeviceType(rep scannerv2.HostReport) (string, string) {
	return matchDeviceType(rep)
}

// isStrongPcSignal reports whether the report carries a strong, explicit
// "this is a personal computer / laptop" signal: a PC hostname keyword
// (notebook/laptop/thinkpad/macbook/…) or a desktop OS label
// (ubuntu/debian/macos/darwin/windows) from an SSH/SNMP banner. It is the gate
// for overriding a handler-set "camera" verdict (applyDeviceBridge): only an
// unambiguous PC wins here — a generic "server" signal does NOT, because
// routers/NAS/NVRs also run RTSP-wrapping web UIs and would be mis-typed.
//
// The keyword set is sourced from device_types.yaml via keywordsForType("pc")
// — the SAME table matchDeviceType uses — so the override gate and the main
// inference engine can never drift (the three-independent-keyword-list bug that
// caused the earlier "z4s" mis-classification is structurally impossible now).
func isStrongPcSignal(rep scannerv2.HostReport) bool {
	return strongTypeSignal(rep, "pc")
}

// isStrongNasSignal reports whether the report carries a strong, explicit
// "this is a NAS / file server / media server" signal: a NAS hostname/brand
// keyword (synology/diskstation/qnap/z4s/zspace/minidlna/readymedia/ugreen/…),
// or an SMB file-sharing service on port 445. It is the gate for overriding a
// handler-set "camera" verdict (applyDeviceBridge): consumer NAS boxes stream
// media over RTSP (极空间 极影视, Synology Video Station, MiniDLNA), so an RTSP
// port alone mis-types them as cameras — but SMB + a NAS vendor is unambiguous.
// A generic server signal does NOT pass this gate (would mis-type routers/NVRs).
// Keywords come from device_types.yaml via keywordsForType("nas").
func isStrongNasSignal(rep scannerv2.HostReport) bool {
	return strongTypeSignal(rep, "nas")
}

// strongTypeSignal is the shared implementation behind isStrongPcSignal /
// isStrongNasSignal: true when the report's host/brand/hint contains a keyword
// from device_types.yaml's host/brand rules for the given type, OR its os_type
// matches an os_rule for that type, OR (for nas only) an smb:445 service.
// Centralized so both gates read the SAME data source as matchDeviceType — the
// override gate and the main engine can never drift.
func strongTypeSignal(rep scannerv2.HostReport, wantType string) bool {
	host := strings.ToLower(rep.Device.Fields["node_hostname"])
	if host == "" {
		host = strings.ToLower(rep.Device.Fields["sys_name"])
	}
	brand := strings.ToLower(rep.Device.Fields["inferred_brand"])
	osType := strings.ToLower(rep.Device.Fields["os_type"])
	// host/brand keyword rules (keywordsForType reads the `rules:` table).
	if containsAny(host+" "+brand, keywordsForType(wantType)...) {
		return true
	}
	// os_rules table — a desktop OS label (ubuntu/debian/macos/windows) is a
	// strong PC signal; android is a strong phone signal.
	for _, r := range deviceTypeRules.OSRules {
		if r.Type == wantType && containsAny(osType, r.Keywords...) {
			return true
		}
	}
	// SMB file sharing is an extra NAS-specific strong signal (not a hostname
	// keyword). Only applies to the nas gate.
	if wantType == "nas" {
		for _, s := range rep.Services {
			if s.Service == "smb" || s.Port == 445 {
				return true
			}
		}
	}
	return false
}

// containsAny reports whether s contains any of subs.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// keep slog referenced for the warn logs above when this file is the only user
var _ = slog.Default
